/**
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 * Copyright (C) 2003 Dinesh G. Dutt <ddutt@cisco.com>
 * Copyright (C) 2003-04 Luca Deri <deri@ntop.org>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include "ntop.h"
#include <stdarg.h>
#include <assert.h>
#include "fcUtils.h"
#include "globals-report.h"

/* **************************************** */

/* ******************* */

char* makeFcHostLink (HostTraffic *el, short mode, short cutName,
                      short compactWWN, char *buf, int buflen) {
  char *tmpStr, tmpbuf[64], colorSpec[64], *linkStr;
  char noLink = FALSE;        /* don't create link for certain spl addr */
  char *devTypeStr, *vendorStr, *vendorName;

  if(el == NULL) {
    traceEvent (CONST_TRACE_ERROR, "makeFcHostLink: Received NULL el\n");
    return("&nbsp;");
  }

  accessAddrResMutex("makeHostLink");
  tmpStr = NULL;
  devTypeStr = "";
  vendorStr = "";

  if(!cutName) {
    if(strncmp (el->fcCounters->hostNumFcAddress, "ff.ff.fd", strlen ("ff.ff.fd")) == 0) {
      tmpStr = "Fabric<br>Controller";
      noLink = TRUE;
    } else if(strncmp (el->fcCounters->hostNumFcAddress, "ff.fc", strlen ("ff.fc")) == 0) {
      safe_snprintf(__FILE__, __LINE__, tmpbuf, 64, "Domain Controller<br>for %s", &el->fcCounters->hostNumFcAddress[6]);
      tmpStr = tmpbuf;
      noLink = TRUE;
    } else if(strncmp (el->fcCounters->hostNumFcAddress, "ff.ff.fe", sizeof ("ff.ff.fe")) == 0) {
      tmpStr = "F_Port<br>Server";
      noLink = TRUE;
    } else if(strncmp (el->fcCounters->hostNumFcAddress, "ff.ff.fc", sizeof ("ff.ff.fc")) == 0) {
      tmpStr = "Directory<br>Server";
      noLink = TRUE;
    } else if(strncmp (el->fcCounters->hostNumFcAddress, "00.00.00", strlen ("00.00.00")) == 0) {
      tmpStr = el->fcCounters->hostNumFcAddress;
      noLink = TRUE;
    } else {
      /* Introduce maybe a picture or string based on HBA's vendor */
      if(el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_FC_WWN) {
	safe_snprintf(__FILE__, __LINE__, tmpbuf, sizeof (tmpbuf), "%.12s<br>%.12s",
		      el->hostResolvedName, &el->hostResolvedName[12]);
	tmpStr = tmpbuf;
      } else
	tmpStr = el->hostResolvedName;

      if(strncmp(el->fcCounters->hostNumFcAddress, "ff", 2) == 0)
	noLink = TRUE;

      linkStr = el->fcCounters->hostNumFcAddress;
    }
  } else {
    if(el->fcCounters->hostFcAddress.domain != FC_ID_SYSTEM_DOMAIN) {
      if(el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_FC_WWN) {
	safe_snprintf(__FILE__, __LINE__, tmpbuf, sizeof (tmpbuf), "%.12s<br>%.12s",
		      el->hostResolvedName, &el->hostResolvedName[12]);
	tmpStr = tmpbuf;
      } else
	tmpStr = el->hostResolvedName;
    } else {
      tmpStr = el->fcCounters->hostNumFcAddress;
      noLink = TRUE;
    }

    linkStr = el->fcCounters->hostNumFcAddress;
  }

  if(el->fcCounters->hostFcAddress.domain && (el->fcCounters->hostFcAddress.domain != FC_ID_SYSTEM_DOMAIN)) {
    if(el->fcCounters->devType == SCSI_DEV_INITIATOR) {
      devTypeStr = "&nbsp;" CONST_IMG_SCSI_INITIATOR;
    }
    else if(el->fcCounters->devType == SCSI_DEV_BLOCK) {
      devTypeStr = "&nbsp;" CONST_IMG_SCSI_DISK;
    } else {
      devTypeStr = "";
    }

    vendorName = getVendorInfo(&el->fcCounters->pWWN.str[2], 1);
    if(vendorName[0] != '\0') {
      if(!strncasecmp (vendorName, "EMULEX CORPORATION",
		       strlen ("EMULEX CORPORATION"))) {
	vendorStr = "&nbsp;" CONST_IMG_FC_VEN_EMULEX;
      }
      else if(!strcasecmp (vendorName, "JNI Corporation")) {
	vendorStr = "&nbsp;" CONST_IMG_FC_VEN_JNI;
      }
      else if(!strcasecmp (vendorName, "BROCADE COMMUNICATIONS SYSTEMS, Inc.")) {
	vendorStr = "&nbsp;" CONST_IMG_FC_VEN_BROCADE;
      }
      else if(!strncmp (vendorName, "EMC", strlen ("EMC"))) {
	vendorStr = "&nbsp;" CONST_IMG_FC_VEN_EMC;
      }
      else if(!strcasecmp (vendorName, "SEAGATE TECHNOLOGY")) {
	vendorStr = "&nbsp;" CONST_IMG_FC_VEN_SEAGATE;
      }
      else {
	vendorStr = "";
      }
    }
    else {
      vendorStr = "";
    }
  }
  else {
    devTypeStr = "";
    vendorStr = "";
  }

  if(mode == FLAG_HOSTLINK_HTML_FORMAT) {
    if(noLink) {
      safe_snprintf(__FILE__, __LINE__, buf, buflen,
		    "<TH "TH_BG" ALIGN=LEFT NOWRAP>%s-%d&nbsp;</TH>",
		    tmpStr, el->fcCounters->vsanId);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, buflen, "<TH "TH_BG" ALIGN=LEFT NOWRAP>"
		    "<A HREF=\"/%s-%d.html\" onMouseOver=\"window.status='"
		    "%s';return true\" onMouseOut=\"window.status=''"
		    ";return true\">%s%s%s</A></TH>", linkStr, el->fcCounters->vsanId,
		    el->fcCounters->hostNumFcAddress, tmpStr, devTypeStr, vendorStr);
    }
  }
  else if(mode == FLAG_HOSTLINK_TEXT_FORMAT) {
    if(noLink) {
      safe_snprintf(__FILE__, __LINE__, buf, buflen, "%s-%d", tmpStr, el->fcCounters->vsanId);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, buflen,
		    "<A HREF=\"/%s-%d.html\" %s NOWRAP "
		    "onMouseOver=\"window.status='%s';return true\" "
		    "onMouseOut=\"window.status='';return true\">%s</A>",
		    linkStr, el->fcCounters->vsanId,
		    makeHostAgeStyleSpec(el, colorSpec, sizeof(colorSpec)),
		    el->fcCounters->hostNumFcAddress, tmpStr);
    }
  }
  else {
    safe_snprintf(__FILE__, __LINE__, buf, buflen, "%s-%d", tmpStr, el->fcCounters->vsanId);
  }

  releaseAddrResMutex ();
  return(buf);
}

/* ******************************* */

char *makeVsanLink (u_short vsanId, short mode, char *buf, int buflen) {
  accessAddrResMutex("makeHostLink");

  if(vsanId) {
    safe_snprintf(__FILE__, __LINE__, buf, buflen,
		  "%s<a href=\"" CONST_VSAN_DETAIL_HTML "?vsan=%d\">%d</a>%s",
		  (mode == FLAG_HOSTLINK_HTML_FORMAT) ? "<th " TH_BG " align=\"right\" NOWRAP>" : "",
		  vsanId, vsanId,
		  (mode == FLAG_HOSTLINK_HTML_FORMAT) ? "</th>" : "");
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, buflen,
		  "%s<a href=\"" CONST_VSAN_DETAIL_HTML "\">-</a>%s",
		  (mode == FLAG_HOSTLINK_HTML_FORMAT) ? "<th " TH_BG " align=\"right\" NOWRAP>" : "",
		  (mode == FLAG_HOSTLINK_HTML_FORMAT) ? "</th>" : "");
  }

  releaseAddrResMutex ();
  return (buf);
}

/* ******************************* */

void printFcHostHeader(HostTraffic *el, char *url, int revertOrder,
		       int column, int hostInfoPage) {
  char buf[LEN_GENERAL_WORK_BUFFER];
  char theLink[256];

  safe_snprintf(__FILE__, __LINE__, theLink, sizeof(theLink),
		"/%s.html?col=%s%d&showF=",
		url,
		revertOrder ? "-" : "",
		column);

  switch(hostInfoPage) {
  case showHostLunStats:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <B>LUN Statistics</B> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostLunGraphs:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <B>LUN Graphs</B> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostScsiSessionBytes:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <B>SCSI Session (Bytes)</B> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <B>SCSI Session (Bytes)</B> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostScsiSessionTimes:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A>]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <B>SCSI Session (Times)</B> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A>]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <B>SCSI Session (Times)</B> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostScsiSessionStatus:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <B>SCSI Session (Status)</B> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <B>SCSI Session (Status)</B> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostScsiSessionTMInfo:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <B>SCSI Session (Task Mgmt)</B> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <B>SCSI Session (Task Mgmt)</B> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostFcSessions:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <B>FC Sessions</B> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <A HREF=%s0>Main Page</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <B>FC Sessions</B> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink);
    }
    break;
  case showHostMainPage:
  default:
    if((el->fcCounters->devType != SCSI_DEV_INITIATOR) &&
       (el->fcCounters->devType != SCSI_DEV_UNINIT)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <B>Main&nbsp;Page</B> ]&nbsp;"
		    "[ <A HREF=%s1>LUN Statistics</A> ]&nbsp;"
		    "[ <A HREF=%s2>LUN Graphs</A> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink, theLink, theLink);
    }
    else {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=RIGHT>"
		    "[ <B>Main&nbsp;Page</B> ]&nbsp;"
		    "[ <A HREF=%s3>SCSI Session (Bytes)</A> ]&nbsp;"
		    "[ <A HREF=%s4>SCSI Session (Times)</A> ]&nbsp;"
		    "[ <A HREF=%s5>SCSI Session (Status)</A> ]&nbsp;"
		    "[ <A HREF=%s6>SCSI Session (Task Mgmt)</A> ]&nbsp;"
		    "[ <A HREF=%s7>FC Sessions</A> ]&nbsp;</p>",
		    theLink, theLink, theLink, theLink, theLink);
    }
    break;
  }

  sendString(buf);
}

/* ******************************* */

int cmpFcFctn(const void *_a, const void *_b)
{
  HostTraffic **a = (HostTraffic **)_a;
  HostTraffic **b = (HostTraffic **)_b;
  Counter a_=0, b_=0, a_val, b_val;
  float fa_=0, fb_=0;
  short floatCompare=0, columnProtoId;

  if((a == NULL) && (b != NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFcFctn() error (1)");
    return(1);
  } else if((a != NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFcFctn() error (2)");
    return(-1);
  } else if((a == NULL) && (b == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "cmpFcFctn() error (3)");
    return(0);
  }

  if(myGlobals.columnSort == FLAG_HOST_DUMMY_IDX) {
    int rc;

    /* Host name */
    accessAddrResMutex("cmpFctn");

    CMP_FC_PORT ((*a), (*b))
      releaseAddrResMutex();
    return(rc);
  } else if(myGlobals.columnSort == FLAG_DOMAIN_DUMMY_IDX) {
    int rc;

    accessAddrResMutex("cmpFctn");

    a_ = (*a)->fcCounters->vsanId, b_ = (*b)->fcCounters->vsanId;

    rc = (a_ < b_) ? -1 : (a_ > b_) ? 1 : 0;

    releaseAddrResMutex();
    return(rc);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO,
	     "reportKind=%d/columnSort=%d/numIpProtosToMonitor=%d\n",
	     myGlobals.reportKind, myGlobals.columnSort, myGlobals.numIpProtosToMonitor);
#endif


  switch(myGlobals.reportKind) {
  case SORT_DATA_RECEIVED_PROTOS:
    switch(myGlobals.columnSort) {
    case 0:
      a_ = (*a)->fcCounters->fcBytesRcvd.value, b_ = (*b)->fcCounters->fcBytesRcvd.value;
      break;
    case 1:
      a_ = (*a)->fcCounters->fcFcpBytesRcvd.value;
      b_ = (*b)->fcCounters->fcFcpBytesRcvd.value;
      break;
    case 2:
      a_ = (*a)->fcCounters->fcElsBytesRcvd.value;
      b_ = (*b)->fcCounters->fcElsBytesRcvd.value;
      break;
    case 3:
      a_ = (*a)->fcCounters->fcDnsBytesRcvd.value;
      b_ = (*b)->fcCounters->fcDnsBytesRcvd.value;
      break;
    case 4:
      a_ = (*a)->fcCounters->fcIpfcBytesRcvd.value;
      b_ = (*b)->fcCounters->fcIpfcBytesRcvd.value;
      break;
    case 5:
      a_ = (*a)->fcCounters->fcSwilsBytesRcvd.value;
      b_ = (*b)->fcCounters->fcSwilsBytesRcvd.value;
      break;
    case 6:
      a_ = (*a)->fcCounters->otherFcBytesRcvd.value;
      b_ = (*b)->fcCounters->otherFcBytesRcvd.value;
      break;
    }
    break;
  case SORT_DATA_RECEIVED_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
	a_ = b_ = 0;
      } else {
	if((*a)->protoIPTrafficInfos[columnProtoId-1] != NULL)
	  a_ = (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value;
	else
	  a_ = 0;

	if((*b)->protoIPTrafficInfos[columnProtoId-1] != NULL)
	  b_ = (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value;
	else
	  b_ = 0;
      }
    } else {
      a_ = (*a)->ipBytesRcvd.value, b_ = (*b)->ipBytesRcvd.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
	/* other IP */
	int i;

	for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  if((*a)->protoIPTrafficInfos[i] != NULL)
	    a_val = ((*a)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*a)->protoIPTrafficInfos[i]->rcvdFromRem.value);
	  else
	    a_val = 0;

	  if((*b)->protoIPTrafficInfos[i] != NULL)
	    b_val = ((*b)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*b)->protoIPTrafficInfos[i]->rcvdFromRem.value);
	  else
	    b_val = 0;

	  /* Better be safe... */
	  if(a_ > a_val) a_ -= a_val; else a_ = 0;
	  if(b_ > b_val) b_ -= b_val; else b_ = 0;
	}
      }
    }
    break;
  case SORT_DATA_RECEIVED_THPT:
    switch(myGlobals.columnSort) {
    case 1:
      fa_ = (*a)->actualRcvdThpt, fb_ = (*b)->actualRcvdThpt, floatCompare = 1;
      break;
    case 2:
      fa_ = (*a)->averageRcvdThpt, fb_ = (*b)->averageRcvdThpt, floatCompare = 1;
      break;
    case 3:
      fa_ = (*a)->peakRcvdThpt, fb_ = (*b)->peakRcvdThpt, floatCompare = 1;
      break;
    case 4:
      fa_ = (*a)->actualRcvdPktThpt, fb_ = (*b)->actualRcvdPktThpt, floatCompare = 1;
      break;
    case 5:
      fa_ = (*a)->averageRcvdPktThpt, fb_ = (*b)->averageRcvdPktThpt, floatCompare = 1;
      break;
    case 6:
      fa_ = (*a)->peakRcvdPktThpt, fb_ = (*b)->peakRcvdPktThpt, floatCompare = 1;
      break;
    }
    break;
  case SORT_DATA_RCVD_HOST_TRAFFIC:
  case SORT_DATA_SENT_HOST_TRAFFIC:
  case SORT_DATA_HOST_TRAFFIC:
    /* Nothing */
    break;
  case SORT_DATA_SENT_PROTOS:
    switch(myGlobals.columnSort) {
    case 0:
      a_ = (*a)->fcCounters->fcBytesSent.value, b_ = (*b)->fcCounters->fcBytesSent.value;
      break;
    case 1:
      a_ = (*a)->fcCounters->fcFcpBytesSent.value;
      b_ = (*b)->fcCounters->fcFcpBytesSent.value;
      break;
    case 2:
      a_ = (*a)->fcCounters->fcElsBytesSent.value;
      b_ = (*b)->fcCounters->fcElsBytesSent.value;
      break;
    case 3:
      a_ = (*a)->fcCounters->fcDnsBytesSent.value;
      b_ = (*b)->fcCounters->fcDnsBytesSent.value;
      break;
    case 4:
      a_ = (*a)->fcCounters->fcIpfcBytesSent.value;
      b_ = (*b)->fcCounters->fcIpfcBytesSent.value;
      break;
    case 5:
      a_ = (*a)->fcCounters->fcSwilsBytesSent.value;
      b_ = (*b)->fcCounters->fcSwilsBytesSent.value;
      break;
    case 6:
      a_ = (*a)->fcCounters->otherFcBytesSent.value;
      b_ = (*b)->fcCounters->otherFcBytesSent.value;
      break;
    }
    break;
  case SORT_DATA_SENT_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
	a_ = b_ = 0;
      } else {
	if((*a)->protoIPTrafficInfos[columnProtoId-1] != NULL)
	  a_ = (*a)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value
	    +(*a)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  a_ = 0;
	if((*b)->protoIPTrafficInfos[columnProtoId-1] != NULL)
	  b_ = (*b)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value
	    +(*b)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  b_ = 0;
      }
    } else {
      a_ = (*a)->ipBytesSent.value, b_ = (*b)->ipBytesSent.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
	/* other IP */
	int i;

	for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  if((*a)->protoIPTrafficInfos[i] != NULL)
	    a_val = ((*a)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*a)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    a_val = 0;

	  if((*b)->protoIPTrafficInfos[i] != NULL)
	    b_val = ((*b)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*b)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    b_val = 0;

	  /* Better be safe... */
	  if(a_ > a_val) a_ -= a_val; else a_ = 0;
	  if(b_ > b_val) b_ -= b_val; else b_ = 0;
	}
      }
    }
    break;
  case SORT_DATA_SENT_THPT:
    switch(myGlobals.columnSort) {
    case 1:
      fa_ = (*a)->actualSentThpt, fb_ = (*b)->actualSentThpt, floatCompare = 1;
      break;
    case 2:
      fa_ = (*a)->averageSentThpt, fb_ = (*b)->averageSentThpt, floatCompare = 1;
      break;
    case 3:
      fa_ = (*a)->peakSentThpt, fb_ = (*b)->peakSentThpt, floatCompare = 1;
      break;
    case 4:
      fa_ = (*a)->actualSentPktThpt, fb_ = (*b)->actualSentPktThpt, floatCompare = 1;
      break;
    case 5:
      fa_ = (*a)->averageSentPktThpt, fb_ = (*b)->averageSentPktThpt, floatCompare = 1;
      break;
    case 6:
      fa_ = (*a)->peakSentPktThpt, fb_ = (*b)->peakSentPktThpt, floatCompare = 1;
      break;
    }
    break;
  case TRAFFIC_STATS:
    /* Nothing */
    break;
  case SORT_DATA_PROTOS:
    switch(myGlobals.columnSort) {
    case 0:
      a_ = (*a)->fcCounters->fcBytesSent.value + (*a)->fcCounters->fcBytesRcvd.value;
      b_ = (*b)->fcCounters->fcBytesSent.value + (*b)->fcCounters->fcBytesRcvd.value;
      break;
    case 1:
      a_ = (*a)->fcCounters->fcFcpBytesSent.value + (*a)->fcCounters->fcFcpBytesRcvd.value;
      b_ = (*b)->fcCounters->fcFcpBytesSent.value + (*b)->fcCounters->fcFcpBytesRcvd.value;
      break;
    case 2:
      a_ = (*a)->fcCounters->fcElsBytesSent.value + (*a)->fcCounters->fcElsBytesRcvd.value;
      b_ = (*b)->fcCounters->fcElsBytesSent.value + (*b)->fcCounters->fcElsBytesRcvd.value;
      break;
    case 3:
      a_ = (*a)->fcCounters->fcDnsBytesSent.value + (*a)->fcCounters->fcDnsBytesRcvd.value;
      b_ = (*b)->fcCounters->fcDnsBytesSent.value + (*b)->fcCounters->fcDnsBytesRcvd.value;
      break;
    case 4:
      a_ = (*a)->fcCounters->fcIpfcBytesSent.value + (*a)->fcCounters->fcIpfcBytesRcvd.value;
      b_ = (*b)->fcCounters->fcIpfcBytesSent.value + (*b)->fcCounters->fcIpfcBytesRcvd.value;
      break;
    case 5:
      a_ = (*a)->fcCounters->fcSwilsBytesSent.value + (*a)->fcCounters->fcSwilsBytesRcvd.value;
      b_ = (*b)->fcCounters->fcSwilsBytesSent.value + (*b)->fcCounters->fcSwilsBytesRcvd.value;
      break;
    case 6:
      a_ = (*a)->fcCounters->otherFcBytesSent.value + (*a)->fcCounters->otherFcBytesRcvd.value;
      b_ = (*b)->fcCounters->otherFcBytesSent.value + (*b)->fcCounters->otherFcBytesRcvd.value;
      break;
    }
    break;
  case SORT_DATA_IP:
    columnProtoId = myGlobals.columnSort - 1;
    if((columnProtoId != -1) && (columnProtoId <= myGlobals.numIpProtosToMonitor)) {
      if(columnProtoId <= 0) {
        a_ = b_ = 0;
      } else {
	if((*a)->protoIPTrafficInfos[columnProtoId-1] != NULL)
	  a_ = (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value+
	    (*a)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  a_ = 0;

	if((*b)->protoIPTrafficInfos[columnProtoId-1] != NULL)
	  b_ = (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdLoc.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->rcvdFromRem.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->sentLoc.value+
	    (*b)->protoIPTrafficInfos[columnProtoId-1]->sentRem.value;
	else
	  b_ = 0;
      }
    } else {
      a_ = (*a)->ipBytesRcvd.value+(*a)->ipBytesSent.value;
      b_ = (*b)->ipBytesRcvd.value+(*b)->ipBytesSent.value;

      if(myGlobals.numIpProtosToMonitor == (columnProtoId-1)) {
        /* other IP */
        int i;

        for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
	  if((*a)->protoIPTrafficInfos[i] != NULL)
	    a_val = ((*a)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*a)->protoIPTrafficInfos[i]->rcvdFromRem.value
		     +(*a)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*a)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    a_val = 0;

	  if((*b)->protoIPTrafficInfos[i] != NULL)
	    b_val = ((*b)->protoIPTrafficInfos[i]->rcvdLoc.value
		     +(*b)->protoIPTrafficInfos[i]->rcvdFromRem.value
		     +(*b)->protoIPTrafficInfos[i]->sentLoc.value
		     +(*b)->protoIPTrafficInfos[i]->sentRem.value);
	  else
	    b_val = 0;
          /* Better be safe... */
          if(a_ > a_val) a_ -= a_val; else a_ = 0;
          if(b_ > b_val) b_ -= b_val; else b_ = 0;
        }
      }
    }
    break;
  case SORT_DATA_THPT:
    switch(myGlobals.columnSort) {
    case 1:
      fa_ = (*a)->actualTThpt;
      fb_ = (*b)->actualTThpt;
      floatCompare = 1;
      break;
    case 2:
      fa_ = (*a)->averageTThpt;
      fb_ = (*b)->averageTThpt;
      floatCompare = 1;
      break;
    case 3:
      fa_ = (*a)->peakTThpt;
      fb_ = (*b)->peakTThpt;
      floatCompare = 1;
      break;
    case 4:
      fa_ = (*a)->actualTPktThpt;
      fb_ = (*b)->actualTPktThpt;
      floatCompare = 1;
      break;
    case 5:
      fa_ = (*a)->averageTPktThpt;
      fb_ = (*b)->averageTPktThpt;
      floatCompare = 1;
      break;
    case 6:
      fa_ = (*a)->peakTPktThpt;
      fb_ = (*b)->peakTPktThpt;
      floatCompare = 1;
      break;
    }
    break;
  }

  /*
    traceEvent(CONST_TRACE_INFO, "%s=%u - %s=%u",
    (*a)->hostResolvedName, (unsigned long)a_,
    (*b)->hostResolvedName, (unsigned long)b_);
  */

  if(floatCompare == 0) {
    if(a_ < b_) {
      return(1);
    } else if(a_ > b_) {
      return(-1);
    } else {
      return(0);
    }
  } else {
    if(fa_ < fb_) {
      return(1);
    } else if(fa_ > fb_) {
      return(-1);
    } else {
      return(0);
    }
  }
}

/* ******************************* */

int cmpFcSessionsFctn (const void *_a, const void *_b) {
  FCSession **a = (FCSession **)_a;
  FCSession **b = (FCSession **)_b;
  int a_, b_;
  int actualDeviceId, rc;

  switch (myGlobals.columnSort) {
  case 1: /* VSAN */
    actualDeviceId = (*a)->deviceId; /* for macro checkSession */
    a_ = (*a)->initiator->fcCounters->vsanId;
    actualDeviceId = (*b)->deviceId;
    b_ = (*b)->initiator->fcCounters->vsanId;
    return ( (a_ > b_) ? 1 : (a_ < b_) ? -1 : 0 );
    break;
  case 2: /* Initiator Alias, pWWN or FC Addr */
    CMP_FC_PORT (((*a)->initiator), ((*b)->initiator))
      return (rc);
    break;
  case 3: /* Target Alias, pWWN or FC Addr */
    CMP_FC_PORT (((*a)->remotePeer), ((*b)->remotePeer))
      return (rc);
    break;
  case 4: /* Data Sent */
    return ( ((*a)->bytesSent.value > (*b)->bytesSent.value) ? 1 :
	     ((*a)->bytesSent.value < (*b)->bytesSent.value) ? -1 : 0);
    break;
  case 5: /* Data Rcvd */
    return ( ((*a)->bytesRcvd.value > (*b)->bytesRcvd.value) ? 1 :
	     ((*a)->bytesRcvd.value < (*b)->bytesRcvd.value) ? -1 : 0);
    break;
  case 6:
    return (((*a)->fcpBytesSent.value > (*b)->fcpBytesSent.value) ? 1 :
	    ((*a)->fcpBytesSent.value < (*b)->fcpBytesSent.value) ? -1 : 0);
    break;
  case 7:
    return (((*a)->fcpBytesRcvd.value > (*b)->fcpBytesRcvd.value) ? 1 :
	    ((*a)->fcpBytesRcvd.value < (*b)->fcpBytesRcvd.value) ? -1 : 0);
    break;
  case 8:
    return (((*a)->fcElsBytesSent.value > (*b)->fcElsBytesSent.value) ? 1 :
	    ((*a)->fcElsBytesSent.value < (*b)->fcElsBytesSent.value) ? -1 : 0);
    break;
  case 9:
    return (((*a)->fcElsBytesRcvd.value > (*b)->fcElsBytesRcvd.value) ? 1 :
	    ((*a)->fcElsBytesRcvd.value < (*b)->fcElsBytesRcvd.value) ? -1 : 0);
    break;
  case 10:
    return (((*a)->fcDnsBytesSent.value > (*b)->fcDnsBytesSent.value) ? 1 :
	    ((*a)->fcDnsBytesSent.value < (*b)->fcDnsBytesSent.value) ? -1 : 0);
    break;
  case 11:
    return (((*a)->fcDnsBytesRcvd.value > (*b)->fcDnsBytesRcvd.value) ? 1 :
	    ((*a)->fcDnsBytesRcvd.value < (*b)->fcDnsBytesRcvd.value) ? -1 : 0);
    break;
  case 12:
    return (((*a)->ipfcBytesSent.value > (*b)->ipfcBytesSent.value) ? 1 :
	    ((*a)->ipfcBytesSent.value < (*b)->ipfcBytesSent.value) ? -1 : 0);
    break;
  case 13:
    return (((*a)->ipfcBytesRcvd.value > (*b)->ipfcBytesRcvd.value) ? 1 :
	    ((*a)->ipfcBytesRcvd.value < (*b)->ipfcBytesRcvd.value) ? -1 : 0);
    break;
  case 14:
    return (((*a)->fcSwilsBytesSent.value > (*b)->fcSwilsBytesSent.value) ? 1 :
	    ((*a)->fcSwilsBytesSent.value < (*b)->fcSwilsBytesSent.value) ? -1 : 0);
    break;
  case 15:
    return (((*a)->fcSwilsBytesRcvd.value > (*b)->fcSwilsBytesRcvd.value) ? 1 :
	    ((*a)->fcSwilsBytesRcvd.value < (*b)->fcSwilsBytesRcvd.value) ? -1 : 0);
    break;
  case 16:
    return (((*a)->otherBytesSent.value > (*b)->otherBytesSent.value) ? 1 :
	    ((*a)->otherBytesSent.value < (*b)->otherBytesSent.value) ? -1 : 0);
    break;
  case 17:
    return (((*a)->otherBytesRcvd.value > (*b)->otherBytesRcvd.value) ? 1 :
	    ((*a)->otherBytesRcvd.value < (*b)->otherBytesRcvd.value) ? -1 : 0);
    break;
  case 18:
    return (CMPTV ((*a)->firstSeen, (*b)->firstSeen));
    break;

  case 19:
    return (CMPTV ((*a)->lastSeen, (*b)->lastSeen));
    break;

  default:
    break;
  }

  return(-1);
}

/* ************************** */

int cmpScsiSessionsFctn (const void *_a, const void *_b)
{
  ScsiSessionSortEntry *a = (ScsiSessionSortEntry *)_a;
  ScsiSessionSortEntry *b = (ScsiSessionSortEntry *)_b;
  int a_, b_, rc;

  switch (myGlobals.columnSort) {
  case 1: /* VSAN */
    a_ = a->initiator->fcCounters->vsanId;
    b_ = b->initiator->fcCounters->vsanId;
    return ( (a_ > b_) ? 1 : (a_ < b_) ? -1 : 0 );
    break;
  case 2: /* Initiator FC Address */
    CMP_FC_PORT ((a->initiator), (b->initiator))
      return (rc);
    break;
  case 3: /* Target FC Address */
    CMP_FC_PORT ((a->target), (b->target))
      return (rc);
    break;
  case 4: /* Data Sent */
    /* The first three entries account for the unknown LUN entry */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return ( (((FCSession *)a->stats)->unknownLunBytesSent.value > b->stats->bytesSent.value) ? 1 :
	       (((FCSession *)a->stats)->unknownLunBytesSent.value < b->stats->bytesSent.value) ? -1 : 0);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return ( (a->stats->bytesSent.value > ((FCSession *)b->stats)->unknownLunBytesSent.value) ? 1 :
	       (a->stats->bytesSent.value < ((FCSession *)b->stats)->unknownLunBytesSent.value) ? -1 : 0);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return ( (((FCSession *)a->stats)->unknownLunBytesSent.value
		> ((FCSession *)b->stats)->unknownLunBytesSent.value) ? 1 :
	       (((FCSession *)a->stats)->unknownLunBytesSent.value <
		((FCSession *)b->stats)->unknownLunBytesSent.value) ? -1 : 0);
    }
    return ( (a->stats->bytesSent.value > b->stats->bytesSent.value) ? 1 :
	     (a->stats->bytesSent.value < b->stats->bytesSent.value) ? -1 : 0);
    break;
  case 5: /* Data Rcvd */
    /* The first three entries account for the unknown LUN entry */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return ( (((FCSession *)a->stats)->unknownLunBytesRcvd.value > b->stats->bytesRcvd.value) ? 1 :
	       (((FCSession *)a->stats)->unknownLunBytesRcvd.value < b->stats->bytesRcvd.value) ? -1 : 0);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return ( (a->stats->bytesRcvd.value > ((FCSession *)b->stats)->unknownLunBytesRcvd.value) ? 1 :
	       (a->stats->bytesRcvd.value < ((FCSession *)b->stats)->unknownLunBytesRcvd.value) ? -1 : 0);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return ( (((FCSession *)a->stats)->unknownLunBytesRcvd.value >
		((FCSession *)b->stats)->unknownLunBytesRcvd.value) ? 1 :
	       (((FCSession *)a->stats)->unknownLunBytesRcvd.value <
		((FCSession *)b->stats)->unknownLunBytesRcvd.value) ? -1 : 0);
    }
    return ( (a->stats->bytesRcvd.value > b->stats->bytesRcvd.value) ? 1 :
	     (a->stats->bytesRcvd.value < b->stats->bytesRcvd.value) ? -1 : 0);
    break;

  case 6:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->scsiRdBytes.value > b->stats->scsiRdBytes.value) ? 1 :
	     (a->stats->scsiRdBytes.value < b->stats->scsiRdBytes.value) ? -1 : 0);
    break;

  case 7:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->scsiWrBytes.value > b->stats->scsiWrBytes.value) ? 1 :
	     (a->stats->scsiWrBytes.value < b->stats->scsiWrBytes.value) ? -1 : 0);
    break;

  case 8:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->scsiOtBytes.value > b->stats->scsiOtBytes.value) ? 1 :
	     (a->stats->scsiOtBytes.value < b->stats->scsiOtBytes.value) ? -1 : 0);
    break;

  case 9:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->minRdSize > b->stats->minRdSize) ? 1:
	     (a->stats->minRdSize < b->stats->minRdSize) ? -1 : 0);
    break;

  case 10:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->maxRdSize > b->stats->maxRdSize) ? 1:
	     (a->stats->maxRdSize < b->stats->maxRdSize) ? -1 : 0);
    break;

  case 11:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->minWrSize > b->stats->minWrSize) ? 1:
	     (a->stats->minWrSize < b->stats->minWrSize) ? -1 : 0);
    break;

  case 12:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->maxWrSize > b->stats->maxWrSize) ? 1:
	     (a->stats->maxWrSize < b->stats->maxWrSize) ? -1 : 0);
    break;

  case 13:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->minXferRdySize > b->stats->minXferRdySize) ? 1:
	     (a->stats->minXferRdySize < b->stats->minXferRdySize) ? -1 : 0);
    break;

  case 14:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->maxXferRdySize > b->stats->maxXferRdySize) ? 1:
	     (a->stats->maxXferRdySize < b->stats->maxXferRdySize) ? -1 : 0);
    break;

  case 15:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->minIops > b->stats->minIops) ? 1:
	     (a->stats->minIops < b->stats->minIops) ? -1 : 0);
    break;

  case 16:
    /* Unknown LUNs don't have any valid info to compare for this field. So
     * we dump them at the end of the list
     */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->maxIops > b->stats->maxIops) ? 1:
	     (a->stats->maxIops < b->stats->maxIops) ? -1 : 0);
    break;

  case 17: /* # Failed Commands */
    /* The first three entries account for the unknown LUN entry */
    if((a->lun == 0xFFFF) && (b->lun != 0xFFFF)) {
      return (1);
    }
    else if((a->lun != 0xFFFF) && (b->lun == 0xFFFF)) {
      return (-1);
    }
    else if((a->lun == 0xFFFF) && (b->lun == 0xFFFF)) {
      return (0);
    }
    return ( (a->stats->numFailedCmds > b->stats->numFailedCmds) ? 1 :
	     (a->stats->numFailedCmds < b->stats->numFailedCmds) ? -1 : 0);
    break;
  case 18:
    return (CMPTV (a->stats->minRTT, b->stats->minRTT));
    break;

  case 19:
    return (CMPTV (a->stats->maxRTT, b->stats->maxRTT));
    break;

  case 20:
    return (CMPTV (a->stats->minXfrRdyRTT, b->stats->minXfrRdyRTT));
    break;

  case 21:
    return (CMPTV (a->stats->maxXfrRdyRTT, b->stats->maxXfrRdyRTT));
    break;

  case 22:
    return (CMPTV (a->stats->minRdFrstDataRTT, b->stats->minRdFrstDataRTT));
    break;

  case 23:
    return (CMPTV (a->stats->maxRdFrstDataRTT, b->stats->maxRdFrstDataRTT));
    break;

  case 24:
    return (CMPTV (a->stats->minWrFrstDataRTT, b->stats->minWrFrstDataRTT));
    break;

  case 25:
    return (CMPTV (a->stats->maxWrFrstDataRTT, b->stats->maxWrFrstDataRTT));
    break;

  case 26:
    return (CMPTV (a->stats->firstSeen, b->stats->firstSeen));
    break;

  case 27:
    return (CMPTV (a->stats->lastSeen, b->stats->lastSeen));
    break;

  case 28:
    return ( (a->stats->chkCondCnt > b->stats->chkCondCnt) ? 1 :
	     (a->stats->chkCondCnt < b->stats->chkCondCnt) ? -1 : 0);
    break;

  case 29:
    return ( (a->stats->busyCnt > b->stats->busyCnt) ? 1 :
	     (a->stats->busyCnt < b->stats->busyCnt) ? -1 : 0);
    break;

  case 30:
    return ( (a->stats->resvConflictCnt > b->stats->resvConflictCnt) ? 1 :
	     (a->stats->resvConflictCnt < b->stats->resvConflictCnt) ? -1
	     : 0);
    break;

  case 31:
    return ( (a->stats->taskSetFullCnt > b->stats->taskSetFullCnt) ? 1 :
	     (a->stats->taskSetFullCnt < b->stats->taskSetFullCnt) ? -1
	     : 0);
    break;

  case 32:
    return ( (a->stats->taskAbrtCnt > b->stats->taskAbrtCnt) ? 1 :
	     (a->stats->taskAbrtCnt < b->stats->taskAbrtCnt) ? -1 : 0);
    break;

  case 33:
    return ( (a->stats->abrtTaskSetCnt > b->stats->abrtTaskSetCnt) ? 1 :
	     (a->stats->abrtTaskSetCnt < b->stats->abrtTaskSetCnt) ? -1 : 0);
    break;

  case 34:
    return ( (a->stats->clearTaskSetCnt > b->stats->clearTaskSetCnt) ? 1 :
	     (a->stats->clearTaskSetCnt < b->stats->clearTaskSetCnt) ? -1 : 0);
    break;

  case 35:
    return ( (a->stats->tgtRstCnt > b->stats->tgtRstCnt) ? 1 :
	     (a->stats->tgtRstCnt < b->stats->tgtRstCnt) ? -1 : 0);
    break;

  case 36:
    return ( (a->stats->lunRstCnt > b->stats->lunRstCnt) ? 1 :
	     (a->stats->lunRstCnt < b->stats->lunRstCnt) ? -1 : 0);
    break;

  case 37:
    return ( (a->stats->lastTgtRstTime > b->stats->lastTgtRstTime) ? 1 :
	     (a->stats->lastTgtRstTime < b->stats->lastTgtRstTime) ? -1 : 0);
    break;

  case 38:
    return ( (a->stats->lastLunRstTime > b->stats->lastLunRstTime) ? 1 :
	     (a->stats->lastLunRstTime < b->stats->lastLunRstTime) ? -1 : 0);
    break;

  default:
    break;
  }

  return(-1);
}

int cmpLunFctn (const void *_a, const void *_b)
{
  LunStatsSortedEntry *a = (LunStatsSortedEntry *)_a;
  LunStatsSortedEntry *b = (LunStatsSortedEntry *)_b;
  Counter a_=0, b_=0;

  switch(myGlobals.columnSort) {
  case 1: /* LU number i.e. LUN */
    return (a->lun > b->lun ? 1 : a->lun < b->lun ? -1 : 0);
    break;

  case 2: /* Data Sent.value */
    a_ = a->stats->bytesSent.value;
    b_ = b->stats->bytesSent.value;
    if(a_ < b_) return(-1); else if(a_ > b_) return(1); else return(0);
    break;

  case 3: /* Data Rcvd.value */
    a_ = a->stats->bytesRcvd.value;
    b_ = b->stats->bytesRcvd.value;

    if(a_ < b_) return(-1); else if(a_ > b_) return(1); else return(0);
    break;

  case 4:
    a_ = a->stats->bytesSent.value + a->stats->bytesRcvd.value;
    b_ = b->stats->bytesSent.value + b->stats->bytesRcvd.value;

    if(a_ < b_) return(-1); else if(a_ > b_) return(1); else return(0);
    break;

  case 5:
    a_ = a->stats->pktSent + a->stats->pktRcvd;
    b_ = b->stats->pktSent + b->stats->pktRcvd;

    if(a_ < b_) return(-1); else if(a_ > b_) return(1); else return(0);
    break;


  default: /* LU number i.e. LUN */
    return (a->lun > b->lun ? 1 : a->lun < b->lun ? -1 : 0);
    break;
  }
}

int cmpVsanFctn (const void *_a, const void *_b)
{
  FcFabricElementHash **a = (FcFabricElementHash **)_a;
  FcFabricElementHash **b = (FcFabricElementHash **)_b;
  Counter a_=0, b_=0;

  switch(myGlobals.columnSort) {
  case 1: /* VSAN */
    return ((*a)->vsanId > (*b)->vsanId ? 1 : (*a)->vsanId < (*b)->vsanId ? -1 : 0);
    break;

  case 2: /* Principal Switch */
    return (memcmp ((void *)&(*a)->principalSwitch.str,
		    (void *)&(*b)->principalSwitch.str, 8));
    break;

  case 3: /* Total bytes */
    a_ = (*a)->totBytes.value;
    b_ = (*b)->totBytes.value;

    if(a_ < b_) return(-1); else if(a_ > b_) return(1); else return(0);
    break;

  case 4: /* Total Frames */
    a_ = (*a)->totPkts.value;
    b_ = (*b)->totPkts.value;

    if(a_ < b_) return(-1); else if(a_ > b_) return(1); else return(0);
    break;
  }

  return(-1);
}

/* ************************************ */

int cmpFcDomainFctn (const void *_a, const void *_b)
{
  SortedFcDomainStatsEntry *a = (SortedFcDomainStatsEntry *)_a;
  SortedFcDomainStatsEntry *b = (SortedFcDomainStatsEntry *)_b;

  switch(myGlobals.columnSort) {
  case 0: /* Rcvd */
    return (a->stats->rcvdBytes.value > b->stats->rcvdBytes.value ? 1 :
	    a->stats->rcvdBytes.value < b->stats->rcvdBytes.value ? -1 : 0);
    break;

  case 2: /* Sent */
  default:
    return (a->stats->sentBytes.value > b->stats->sentBytes.value ? 1 :
	    a->stats->sentBytes.value < b->stats->sentBytes.value ? -1 : 0);
    break;
  }
}

/* ************************************ */

void printFcHostTrafficStats(HostTraffic *el, int actualDeviceId) {
  Counter totalSent, totalRcvd;
  Counter actTotalSent, actTotalRcvd;
  char buf[LEN_GENERAL_WORK_BUFFER];
  char linkName[LEN_GENERAL_WORK_BUFFER/2];

  totalSent = el->fcCounters->fcBytesSent.value;
  totalRcvd = el->fcCounters->fcBytesRcvd.value;

  printHostHourlyTraffic(el);

  /*   printPacketStats(el, actualDeviceId); */


  if((totalSent == 0) && (totalRcvd == 0))
    return;

  printSectionTitle("Protocol Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR><TH "TH_BG" WIDTH=100 "DARK_BG">Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2 "DARK_BG">Total&nbsp;Bytes&nbsp;Sent</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=2 "DARK_BG">Total&nbsp;Bytes&nbsp;Rcvd</TH></TR>\n");

  actTotalSent = el->fcCounters->fcFcpBytesSent.value;
  actTotalRcvd = el->fcCounters->fcFcpBytesRcvd.value;

  printTableDoubleEntry(buf, sizeof(buf), "SCSI", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->fcCounters->fcElsBytesSent.value;
  actTotalRcvd = el->fcCounters->fcElsBytesRcvd.value;

  printTableDoubleEntry(buf, sizeof(buf), "ELS", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->fcCounters->fcDnsBytesSent.value;
  actTotalRcvd = el->fcCounters->fcDnsBytesRcvd.value;

  printTableDoubleEntry(buf, sizeof(buf), "NS", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->fcCounters->fcSwilsBytesSent.value;
  actTotalRcvd = el->fcCounters->fcSwilsBytesRcvd.value;

  printTableDoubleEntry(buf, sizeof(buf), "SWILS", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->fcCounters->fcIpfcBytesSent.value;
  actTotalRcvd = el->fcCounters->fcIpfcBytesRcvd.value;

  printTableDoubleEntry(buf, sizeof(buf), "IP/FC", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  actTotalSent = el->fcCounters->otherFcBytesSent.value;
  actTotalRcvd = el->fcCounters->otherFcBytesRcvd.value;

  printTableDoubleEntry(buf, sizeof(buf), "Others", CONST_COLOR_1, (float)actTotalSent/1024,
			100*((float)SD(actTotalSent, totalSent)),
			(float)actTotalRcvd/1024,
			100*((float)SD(actTotalRcvd, totalRcvd)));

  {
    totalSent = el->fcCounters->fcBytesSent.value;
    totalRcvd = el->fcCounters->fcBytesRcvd.value;

    if((totalSent > 0) || (totalRcvd > 0)) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), 
		    "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Protocol Distribution</TH>",
		    getRowColor());
      sendString(buf);

      if(el->fcCounters->hostNumFcAddress[0] != '\0') {
	strncpy (linkName, fc_to_str ((u_int8_t *)&el->fcCounters->hostFcAddress), sizeof (linkName));
      }

      if(totalSent > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD WIDTH=250 "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
		      "<iframe frameborder=0 SRC=hostFcTrafficDistrib-%s"CHART_FORMAT"?1 "
		      "ALT=\"Sent Traffic Distribution for %s\" width=400 height=250></iframe></TD>",
		      linkName,
		      fc_to_str ((u_int8_t *)&el->fcCounters->hostFcAddress));
	sendString(buf);
      } else {
	sendString("<TD width=250 "TD_BG" ALIGN=RIGHT COLSPAN=2 WIDTH=250>&nbsp;</TD>");
      }

      if(totalRcvd > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white><IMG SRC=hostFcTrafficDistrib-"
		      "%s"CHART_FORMAT" ALT=\"Received Traffic Distribution for %s\"></TD>",
		      linkName,
		      fc_to_str ((u_int8_t *)&el->fcCounters->hostFcAddress));
	sendString(buf);
      } else {
	sendString("<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 WIDTH=250>&nbsp;</TD>");
      }

      sendString("</TD></TR>");

#ifdef NOT_YET
      if((el->fcCounters->fcFcpBytesSent.value + el->fcCounters->fcElsBytesSent.value + el->fcCounters->fcDnsBytesSent.value + el->otherFcBytesSent.value)
         > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>Traffic Distribution</TH>",
                      getRowColor());
	sendString(buf);

	if((el->fcCounters->fcFcpBytesSent.value + el->fcCounters->fcElsBytesSent.value + el->fcCounters->fcDnsBytesSent.value + el->otherFcBytesSent.value) > 0) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white>"
			"<iframe frameborder=0 SRC=hostIPTrafficDistrib-%s"CHART_FORMAT"?1 "
			"ALT=\"Sent Traffic Distribution for %s\"  width=400 height=250></iframe></TD>",
			fc_to_str(&el->fcCounters->hostFcAddress), fc_to_str (&el->fcCounters->hostFcAddress));
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	if((el->fcCounters->fcFcpBytesRcvd.value + el->fcCounters->fcElsBytesRcvd.value + el->fcCounters->fcDnsBytesRcvd.value + el->otherFcBytesRcvd.value) > 0) {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"<TD "TD_BG" ALIGN=RIGHT COLSPAN=2 BGCOLOR=white><iframe frameborder=0 SRC=hostIPTrafficDistrib-"
			"%s"CHART_FORMAT" ALT=\"Received Traffic Distribution for %s\" width=400 height=250></iframe></TD></TR>",
			fc_to_str(&el->fcCounters->hostFcAddress), fc_to_str (&el->fcCounters->hostFcAddress));
	  sendString(buf);
	} else
	  sendString("<TD "TD_BG" COLSPAN=2 WIDTH=250>&nbsp;</TD>");

	sendString("</TR>");
      }
#endif /* NOT_YET */
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ************************************ */

void printFcHostContactedPeers(HostTraffic *el, int actualDeviceId)
{
  u_int i, titleSent = 0;
  char buf[LEN_GENERAL_WORK_BUFFER], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];
  HostTraffic tmpEl;

  if((el->pktSent.value != 0) || (el->pktRcvd.value != 0)) {
    int ok =0;

    /* Also allocate space for FC info structure */
    tmpEl.fcCounters = NULL;
    if(allocFcScsiCounters(&tmpEl) == NULL) return;
    tmpEl.l2Family = FLAG_HOST_TRAFFIC_AF_FC;
    tmpEl.fcCounters->devType = SCSI_DEV_UNINIT;
    tmpEl.magic = CONST_MAGIC_NUMBER;

    for(i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
      if(((!emptySerial(&el->contactedSentPeers.peersSerials[i])
	   && (!cmpSerial(&el->contactedSentPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial)))
	  || ((!emptySerial(&el->contactedRcvdPeers.peersSerials[i])
	       && (!cmpSerial(&el->contactedRcvdPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial)))))) {
	ok = 1;
	break;
      }

    if(ok) {
      HostTraffic *el2;
      int numEntries;

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if(!emptySerial(&el->contactedSentPeers.peersSerials[i])
	   && (!cmpSerial(&el->contactedSentPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))) {
	  if((el2 = quickHostLink(el->contactedSentPeers.peersSerials[i],
				  myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(numEntries == 0) {
	      printSectionTitle("Last Contacted Peers");

	      titleSent = 1;
	      sendString("<CENTER>\n"
			 "<TABLE BORDER=0 "TABLE_DEFAULTS"><TR><TD "TD_BG" VALIGN=TOP>\n");

	      sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>"
			 "<TR "TR_ON"><TH "TH_BG" "DARK_BG" now>Sent To</TH>"
			 "<TH "TH_BG" "DARK_BG">Address</TH></TR>\n");
	    }

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
			  "<TD "TD_BG" ALIGN=RIGHT nowrap>%s&nbsp;</TD></TR>\n",
			  getRowColor(),
			  makeFcHostLink(el2,
					 FLAG_HOSTLINK_TEXT_FORMAT,
					 0, 0, hostLinkBuf,
					 sizeof (hostLinkBuf)),
			  el2->fcCounters->hostNumFcAddress);

	    sendString(buf);
	    numEntries++;
	  }
	}

      if(numEntries > 0) {
	sendString("</TABLE>"TABLE_OFF"</TD><TD "TD_BG" VALIGN=TOP>\n");
      } else {
	sendString("&nbsp;</TD><TD "TD_BG">\n");
      }

      /* ***************************************************** */

      for(numEntries = 0, i=0; i<MAX_NUM_CONTACTED_PEERS; i++)
	if((!emptySerial(&el->contactedRcvdPeers.peersSerials[i]))
	   && (!cmpSerial(&el->contactedRcvdPeers.peersSerials[i], &myGlobals.otherHostEntry->hostSerial))) {
	  if((el2 = quickHostLink(el->contactedRcvdPeers.peersSerials[i],
				  myGlobals.actualReportDeviceId, &tmpEl)) != NULL) {
	    if(numEntries == 0) {
	      if(!titleSent) printSectionTitle("Last Contacted Peers");
	      sendString("<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">"
			 "<TR "TR_ON"><TH "TH_BG" "DARK_BG">Received From</TH>"
			 "<TH "TH_BG" "DARK_BG">Address</TH></TR>\n");
	    }

	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT>%s</TH>"
			  "<TD "TD_BG" ALIGN=RIGHT nowrap>%s</TD></TR>\n",
			  getRowColor(),
			  makeFcHostLink(el2,
					 FLAG_HOSTLINK_TEXT_FORMAT,
					 0, 0, hostLinkBuf,
					 sizeof (hostLinkBuf)),
			  el2->fcCounters->hostNumFcAddress);

	    sendString(buf);
	    numEntries++;
	  }
	}

      if(numEntries > 0) {
	sendString("</TABLE>"TABLE_OFF"\n");
      }

      sendString("</TD></TR></TABLE>"TABLE_OFF"<P>\n");
      sendString("</CENTER>\n");
    } /* ok */

    if(tmpEl.fcCounters != NULL) {
      free (tmpEl.fcCounters);
    }
  }
  else {
    traceEvent (CONST_TRACE_ALWAYSDISPLAY, "printFcHostContactedPeers: else part\n");
  }

}

/* ************************************ */

void printFcHostDetailedInfo(HostTraffic *el, int actualDeviceId)
{
  char buf[LEN_GENERAL_WORK_BUFFER], buf1[64];
  float percentage;
  Counter total, tot1;
  char *vendorName;
  char formatBuf[32], formatBuf1[32], formatBuf2[32];

  accessAddrResMutex("printFcHostDetailedInfo");

  buf1[0]=0;

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about %s\n", el->hostResolvedName);

  releaseAddrResMutex();
  printSectionTitle(buf);
  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n");

  accessAddrResMutex("printAllSessions-2");

  if(el->fcCounters->vsanId) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%d%s</TD></TR>\n",
		  getRowColor(), "VSAN",
		  el->fcCounters->vsanId,
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
  }
  else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "N/A%s</TD></TR>\n",
		  getRowColor(), "VSAN",
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
  }
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
                "%s%s</TD></TR>\n",
                getRowColor(), "FC_ID",
                el->fcCounters->hostNumFcAddress,
                myGlobals.separator /* it avoids empty cells not to be rendered */);
  sendString(buf);

  if(el->fcCounters->pWWN.str[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Port&nbsp;WWN",
		  fcwwn_to_str ((u_int8_t *)&el->fcCounters->pWWN),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);
  }

  if(el->fcCounters->nWWN.str[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Node&nbsp;WWN",
		  fcwwn_to_str ((u_int8_t *)&el->fcCounters->nWWN),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);
  }

  vendorName = getVendorInfo(&el->fcCounters->pWWN.str[2], 1);
  if(vendorName[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Nw&nbsp;Board&nbsp;Vendor",
		  vendorName,
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
                "<TD "TD_BG" ALIGN=RIGHT>"
                "%s&nbsp;&nbsp;-&nbsp;&nbsp;%s&nbsp;[%s]</TD></TR>\n",
                getRowColor(),
                "First/Last&nbsp;Seen",
                formatTime(&(el->firstSeen), formatBuf, sizeof (formatBuf)),
                formatTime(&(el->lastSeen), formatBuf1, sizeof (formatBuf1)),
                formatSeconds(el->lastSeen - el->firstSeen, formatBuf2,
                              sizeof (formatBuf2)));
  sendString(buf);

  if(el->fcCounters->numOffline.value) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Number&nbsp;Of&nbsp;Times&nbsp;Offline",
		  formatPkts(el->fcCounters->numOffline.value, formatBuf, sizeof (formatBuf)),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString (buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Last&nbsp;Offline&nbsp;Time",
		  formatTime(&el->fcCounters->lastOfflineTime, formatBuf, sizeof (formatBuf)),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString (buf);

    if(el->fcCounters->lastOnlineTime) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s%s</TD></TR>\n",
		    getRowColor(), "Last&nbsp;Online&nbsp;Time",
		    formatTime(&el->fcCounters->lastOnlineTime, formatBuf, sizeof (formatBuf)),
		    myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString (buf);
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH>"
		"<TD "TD_BG" ALIGN=RIGHT>%d&nbsp;</TD></TR>\n",
		getRowColor(), "MTU", el->fcCounters->fcRecvSize);
  sendString(buf);

  if(el->fcCounters->devType != SCSI_DEV_UNINIT) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "SCSI&nbsp;Device&nbsp;Type",
		  el->fcCounters->devType == SCSI_DEV_BLOCK ? "Target, Block" :
		  el->fcCounters->devType == SCSI_DEV_SSC  ? "Target, Tape" :
		  el->fcCounters->devType == SCSI_DEV_UNKNOWN ? "Target, Unknown" :
		  el->fcCounters->devType == SCSI_DEV_INITIATOR ? "Initiator" : "Other",
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);
  }

  if((el->fcCounters->devType != SCSI_DEV_UNINIT) &&
     (el->fcCounters->devType != SCSI_DEV_INITIATOR)) {

    if(el->fcCounters->vendorId[0] != '\0') {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s%s</TD></TR>\n",
		    getRowColor(), "Device&nbsp;Vendor",
		    el->fcCounters->vendorId,
		    myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }

    if(el->fcCounters->productId[0] != '\0') {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s%s</TD></TR>\n",
		    getRowColor(), "Product&nbsp;Name",
		    el->fcCounters->productId,
		    myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }

    if(el->fcCounters->productRev[0] != '\0') {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s%s</TD></TR>\n",
		    getRowColor(), "Product&nbsp;Revision",
		    el->fcCounters->productRev,
		    myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s"
                "</TH><TD "TD_BG" ALIGN=RIGHT>"
                "%s/%s Pkts</TD></TR>\n",
                getRowColor(), "Total&nbsp;Data&nbsp;Rcvd",
                formatBytes(el->fcCounters->fcBytesRcvd.value, 1,
                            formatBuf, sizeof (formatBuf)),
                formatPkts(el->pktRcvd.value, formatBuf1,
                           sizeof (formatBuf1)));
  sendString(buf);

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s"
                "</TH><TD "TD_BG" ALIGN=RIGHT>"
                "%s/%s Pkts</TD></TR>\n",
                getRowColor(), "Total&nbsp;Data&nbsp;Sent",
                formatBytes(el->fcCounters->fcBytesSent.value, 1, formatBuf,
                            sizeof (formatBuf)),
                formatPkts(el->pktSent.value, formatBuf1,
                           sizeof (formatBuf1)));
  sendString(buf);

  total = el->pktSent.value+el->pktRcvd.value;
  if(total > 0) {
    percentage = ((float)el->pktSent.value*100)/((float)total);
    printTableEntryPercentage(buf, sizeof(buf), "Sent&nbsp;vs.&nbsp;Rcvd&nbsp;Pkts",
			      "Sent", "Rcvd", -1, percentage, 0, 0);
  }

  total = el->fcCounters->fcBytesSent.value+el->fcCounters->fcBytesRcvd.value;
  if(total > 0) {
    percentage = ((float)el->fcCounters->fcBytesSent.value*100)/((float)total);
    printTableEntryPercentage(buf, sizeof(buf), "Sent&nbsp;vs.&nbsp;Rcvd&nbsp;Data",
			      "Sent", "Rcvd", -1, percentage, 0, 0);
  }

  tot1 = el->fcCounters->class3Sent.value + el->fcCounters->class3Rcvd.value;
  if((total > 0) && (tot1 > 0)) {
    percentage = (((float)tot1*100)/total);
    printTableEntryPercentage(buf, sizeof(buf), "Class&nbsp;3&nbsp;vs.&nbsp;Other&nbsp;Traffic",
			      "Class 3", "Other Classes", -1, percentage, 0, 0);
  }

  tot1 = el->fcCounters->fcFcpBytesRcvd.value + el->fcCounters->fcFcpBytesSent.value;
  if((total > 0) && (tot1 > 0)) {
    percentage = (((float)tot1*100)/total);
    printTableEntryPercentage(buf, sizeof(buf), "SCSI&nbsp;vs.&nbsp;Others&nbsp;Traffic",
			      "SCSI", "Others", -1, percentage, 0, 0);
  }

  tot1 = el->fcCounters->scsiReadBytes.value + el->fcCounters->scsiWriteBytes.value;
  if(tot1 > 0) {
    percentage = (((float)el->fcCounters->scsiReadBytes.value*100)/tot1);
    printTableEntryPercentage(buf, sizeof(buf), "SCSI&nbsp;Read&nbsp;vs.&nbsp;Write&nbsp;Bytes",
			      "SCSI Read", "SCSI Write", -1, percentage, 0, 0);
  }

  /* RRD */
  if(el->fcCounters->hostNumFcAddress[0] != '\0') {
    if(strcmp(myGlobals.device[0].name, "pcap-file")) {
      struct stat statbuf;
      char key[128];

      safe_snprintf(__FILE__, __LINE__, key, sizeof (key), "%s-%d",
		    el->fcCounters->hostNumFcAddress, el->fcCounters->vsanId);

      /* Do NOT add a '/' at the end of the path because Win32 will complain about it */
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/interfaces/%s/hosts/%s",
		    myGlobals.rrdPath != NULL ? myGlobals.rrdPath : ".",
		    myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		    dotToSlash(key));

      if(stat(buf, &statbuf) == 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		      "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">Historical Data</TH>\n"
		      "<TD "TD_BG" ALIGN=\"right\">"
		      "[ <a href=\"/" CONST_PLUGINS_HEADER
		      "rrdPlugin?action=list&amp;key=interfaces/%s/hosts/%s&amp;title=host%%20%s\">"
		      "<img valign=\"top\" border=\"0\" src=\"/graph.gif\""
		      " class=tooltip alt=\"view rrd graphs of historical data for this host\"></a> ]"
		      "</TD></TR>\n",
		      getRowColor(),
		      myGlobals.device[myGlobals.actualReportDeviceId].uniqueIfName,
		      dotToSlash(key),
		      el->hostResolvedName[0] != '\0' ? el->hostResolvedName : el->fcCounters->hostNumFcAddress);
	sendString(buf);
      }
    }
  }

  /* **************************** */

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

void printScsiLunStats (HostTraffic *el, int actualDeviceId, int sortedColumn,
                        int revertOrder, int pageNum, char *url)
{

  u_int idx, numEntries, skipEntries = 0;
  int printedEntries=0;
  int duration;
  LunStatsSortedEntry sortedLunTbl[MAX_LUNS_SUPPORTED];
  LunStatsSortedEntry *entry;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign;
  char formatBuf[32], formatBuf1[32], formatBuf2[32], formatBuf3[32],
    formatBuf4[32], formatBuf5[32];
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64], pageUrl[64];
  char pcapFilename[128];
  Counter dataSent, dataRcvd;

  if((el->fcCounters->devType == SCSI_DEV_UNINIT) ||
     (el->fcCounters->devType == SCSI_DEV_INITIATOR)) {
    printNoDataYet();
    return;
  }

  printSectionTitle("LUN Statistics");

  memset(buf, 0, sizeof(buf));
  memset(sortedLunTbl, 0, sizeof (sortedLunTbl));

  myGlobals.columnSort = sortedColumn;

  for (idx=0, numEntries=0; idx < MAX_LUNS_SUPPORTED; idx++) {
    if(el->fcCounters->activeLuns[idx] != NULL) {
      sortedLunTbl[numEntries].lun = idx;
      sortedLunTbl[numEntries++].stats = el->fcCounters->activeLuns[idx];
    }
  }

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  if(numEntries > 0) {

    myGlobals.columnSort = sortedColumn;
    qsort(sortedLunTbl, numEntries, sizeof(LunStatsSortedEntry), cmpLunFctn);

    /* Need to add info about page in Hosts Info mode */
    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
		  "<A HREF=/%s.html?showF=%d&page=%d&col=%s", url,
		  showHostLunStats, pageNum, sign);
    safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
		  "<A HREF=/%s.html?showF=%d&page=%d&col=", url,
		  showHostLunStats, pageNum);
    safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html?showF=%d",
		  url, showHostLunStats);

    if(abs(myGlobals.columnSort) == 1) {
      arrow[1] = arrowGif;
      theAnchor[1] = htmlAnchor;
    } else {
      arrow[1] = "";
      theAnchor[1] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 2)  {
      arrow[2] = arrowGif;
      theAnchor[2] = htmlAnchor;
    } else {
      arrow[2] = "";
      theAnchor[2] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 3) {
      arrow[3] = arrowGif;
      theAnchor[3] = htmlAnchor;
    } else {
      arrow[3] = "";
      theAnchor[3] = htmlAnchor1;
    }

    if(abs(myGlobals.columnSort) == 4) {
      arrow[4] = arrowGif;
      theAnchor[4] = htmlAnchor;
    } else {
      arrow[4] = "";
      theAnchor[4] = htmlAnchor1;
    }

    /* Added by Ola Lundqvist <opal@debian.org> */
#ifdef WIN32
    safe_snprintf(__FILE__, __LINE__, pcapFilename, sizeof(pcapFilename),
		  "file:%s\ntop-suspicious-pkts.none.pcap",
		  myGlobals.runningPref.pcapLogBasePath);

#else
    safe_snprintf(__FILE__, __LINE__, pcapFilename, sizeof(pcapFilename),
		  "file://%s/ntop-suspicious-pkts.none.pcap",
		  myGlobals.runningPref.pcapLogBasePath);
#endif

    sendString("<CENTER>\n");
    safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		  ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%%><TR "TR_ON">"
		  "<TH "TH_BG" >%s1>LUN%s</A></TH>"
		  "<TH "TH_BG" COLSPAN=2>Total&nbsp;Bytes</TH>"
		  "<TH "TH_BG" COLSPAN=3>Data&nbsp;Bytes</TH>"
		  "<TH "TH_BG" COLSPAN=2>Read&nbsp;Size</TH>"
		  "<TH "TH_BG" COLSPAN=2>Write&nbsp;Size</TH>"
		  "<TH "TH_BG" COLSPAN=2>Xfer&nbsp;Rdy&nbsp;Size</TH>"
		  "<TH "TH_BG">#&nbsp;Failed&nbsp;Cmds</TH>"
		  "<TH "TH_BG" >Duration(secs)</TH>"
		  "<TH "TH_BG" >Last&nbsp;Seen</TH>"
		  "</TR>\n",
		  theAnchor[1], arrow[1]);

    sendString(buf);

    safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		  "<TR "TR_ON" %s>"
		  "<TH "TH_BG"><br></TH>"
		  "<TH "TH_BG">%s2>Sent%s</A></TH>"
		  "<TH "TH_BG">%s3>Rcvd%s</A></TH>"
		  "<TH "TH_BG">Read</TH>"
		  "<TH "TH_BG">Write</TH>"
		  "<TH "TH_BG">Other</TH>"
		  "<TH "TH_BG">Min</TH>"
		  "<TH "TH_BG">Max</TH>"
		  "<TH "TH_BG">Min</TH>"
		  "<TH "TH_BG">Max</TH>"
		  "<TH "TH_BG">Min</TH>"
		  "<TH "TH_BG">Max</TH>"
		  "<TH "TH_BG"><br></TH>"
		  "<TH "TH_BG"><br></TH>"
		  "<TH "TH_BG"><br></TH>"
		  "</TR>\n",
		  getRowColor(), theAnchor[2], arrow[2], theAnchor[3],
		  arrow[3]);

    sendString(buf);

    for(idx=0; idx<numEntries; idx++) {

      if(revertOrder)
	entry = &sortedLunTbl[numEntries-idx-1];
      else
	entry = &sortedLunTbl[idx];

      if((skipEntries++) < pageNum*myGlobals.runningPref.maxNumLines) {
	continue;
      }

      dataSent = entry->stats->bytesSent.value;
      dataRcvd = entry->stats->bytesRcvd.value;
      duration = entry->stats->lastSeen.tv_sec-entry->stats->firstSeen.tv_sec;

      if(entry != NULL) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "</TR>\n",
		      getRowColor(),
		      entry->lun,
		      formatBytes (dataSent, 1, formatBuf, sizeof (formatBuf)),
		      formatBytes (dataRcvd, 1, formatBuf1, sizeof (formatBuf1)),
		      formatBytes (entry->stats->scsiRdBytes.value, 1,
				   formatBuf2, sizeof (formatBuf2)),
		      formatBytes (entry->stats->scsiWrBytes.value, 1,
				   formatBuf3, sizeof (formatBuf3)),
		      formatBytes (entry->stats->scsiOtBytes.value, 1,
				   formatBuf4, sizeof (formatBuf4)),
		      entry->stats->minRdSize,
		      entry->stats->maxRdSize,
		      entry->stats->minWrSize,
		      entry->stats->maxWrSize,
		      entry->stats->minXferRdySize,
		      entry->stats->maxXferRdySize,
		      entry->stats->numFailedCmds,
		      duration,
		      formatTime((time_t *)&(entry->stats->lastSeen),
				 formatBuf5, sizeof (formatBuf5))
		      );

	sendString(buf);

	/* Avoid huge tables */
	if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	  break;
      }
    }

    sendString("</TABLE>"TABLE_OFF"\n");
    sendString("</CENTER>\n");

    addPageIndicator(pageUrl, pageNum, numEntries, myGlobals.runningPref.maxNumLines,
		     revertOrder, sortedColumn, -1);

    printFooterHostLink();
  } else
    printNoDataYet();
}

void printScsiLunGraphs (HostTraffic *el, int actualDeviceId)
{
  char buf[LEN_GENERAL_WORK_BUFFER], buf1[64];

  buf[0] = buf1[0] = '\0';

  if((el->fcCounters->devType == SCSI_DEV_UNINIT) ||
     (el->fcCounters->devType == SCSI_DEV_INITIATOR)) {
    printNoDataYet();
    return;
  }

  //printHTMLheader ("LUN Traffic Graphs (Top 25)", 0, 0);

  printSectionTitle("LUN Traffic (Total Bytes)");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
                "<iframe frameborder=0 SRC=\"" CONST_BAR_LUNSTATS_DIST "-%s" CHART_FORMAT "?1 "
                "ALT=\"LUN Traffic (Total Bytes) %s\" width=400 height=250></iframe></TH></TR>",
                el->fcCounters->hostNumFcAddress, el->fcCounters->hostNumFcAddress);
  sendString(buf);

  printSectionTitle("LUN Traffic (Total Frames)");

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		"<iframe frameborder=0 SRC=drawLunStatsPktsDistribution-%s"CHART_FORMAT"?1 ALT=\"LUN Frames Statistics "
		"LUN Traffic (Total Frames) %s\" width=400 height=250></iframe></TH></TR>",
                el->fcCounters->hostNumFcAddress, el->fcCounters->hostNumFcAddress);
  sendString(buf);
}

void printVsanDetailedInfo (u_int vsanId, int actualDeviceId)
{
  char buf[LEN_GENERAL_WORK_BUFFER], buf1[64];
  char formatBuf[32], formatBuf1[32];
  int i;
  char *vendorName;
  u_int idx;
  FcFabricElementHash *hash, **theHash;
  FcDomainList *domListEntry;

  accessAddrResMutex("printAllSessionsHTML");

  buf1[0]=0;

  if(vsanId) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about VSAN %d\n", vsanId);
  }
  else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "Info about VSAN\n");
  }

  releaseAddrResMutex();

  printSectionTitle(buf);

  if((theHash = myGlobals.device[actualDeviceId].vsanHash) == NULL) {
    printNoDataYet ();
    return;
  }

  /* Locate the entry belonging to the VSAN */
  idx = vsanId % MAX_ELEMENT_HASH;

  if(theHash[idx] == NULL) {
    printNoDataYet ();
    return;
  }

  while (1) {
    if(theHash[idx]->vsanId == vsanId)
      break;

    idx = (idx+1) % MAX_ELEMENT_HASH;
    if(++idx == MAX_ELEMENT_HASH) {
      printNoDataYet ();
      return;
    }
  }

  hash = theHash[idx];

  sendString("<CENTER>\n");
  sendString("<P>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%>\n");

  accessAddrResMutex("printAllSessions-2");

  if(hash->principalSwitch.str[0] != '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Principal&nbsp;Switch",
		  fcwwn_to_str (&hash->principalSwitch.str[0]),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);

    vendorName = getVendorInfo(&hash->principalSwitch.str[2], 1);
    if(vendorName[0] != '\0') {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		    "%s%s</TD></TR>\n",
		    getRowColor(), "Principal&nbsp;Switch&nbsp;Vendor",
		    vendorName,
		    myGlobals.separator /* it avoids empty cells not to be rendered */);
      sendString(buf);
    }
  }

  if(hash->fabricConfStartTime) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Last&nbsp;Fabric&nbsp;Configuration&nbsp;Started&nbsp;At",
		  formatTime(&hash->fabricConfStartTime, formatBuf,
			     sizeof (formatBuf)),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);
  }

  if(hash->zoneConfStartTime) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR %s><TH "TH_BG" ALIGN=LEFT "DARK_BG">%s</TH><TD "TD_BG" ALIGN=RIGHT>"
		  "%s%s</TD></TR>\n",
		  getRowColor(), "Last&nbsp;Zone&nbsp;Configuration&nbsp;Started&nbsp;At",
		  formatTime(&hash->zoneConfStartTime, formatBuf,
			     sizeof (formatBuf)),
		  myGlobals.separator /* it avoids empty cells not to be rendered */);
    sendString(buf);
  }

  sendString("<TR><TH "TH_BG" align=left "DARK_BG">Switches In Fabric</TH>"
	     "<TD "TD_BG" ALIGN=RIGHT>");

  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=100%%>\n<TR "TR_ON"><TH "TH_BG" "DARK_BG">Domain</TH>"
	     "<TH "TH_BG" "DARK_BG">WWN</TH><TH "TH_BG" "DARK_BG">Switch Vendor</TH>"
	     "<TH "TH_BG" "DARK_BG">Bytes Sent</TH><TH "TH_BG" "DARK_BG">Bytes Rcvd</TH></TR>\n");

  i = hash->domainListLen;
  domListEntry = hash->domainList;

  if(domListEntry != NULL) {
    while ((i > 0) && (domListEntry != NULL)) {
      if(domListEntry->recordType == 1 /* TBD: Change 01 to meaningful
					* define */) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf), "<TR "TR_ON" %s><TD "TD_BG" align=right>%x</TD>"
		      "<TD "TD_BG" align=right>%s</TD><TD "TD_BG" align=right>%s</TD>"
		      "<TD "TD_BG" align=right>%s</TD><TD "TD_BG" align=right>%s</TD>",
		      getRowColor(), domListEntry->domainId,
		      fcwwn_to_str ((u_int8_t *)&domListEntry->switchWWN.str),
		      getVendorInfo (&domListEntry->switchWWN.str[2], 1),
		      formatBytes (hash->domainStats[domListEntry->domainId].sentBytes.value, 1,
				   formatBuf, sizeof (formatBuf)),
		      formatBytes (hash->domainStats[domListEntry->domainId].rcvdBytes.value, 1,
				   formatBuf1, sizeof (formatBuf1))
		      );
	sendString (buf);
      }

      i -= 16;
      domListEntry = (FcDomainList *)((char *)domListEntry + 16);
    }
  }
  else {
    /* Print just the stats, without more switch information */
    for (i = 1; i < MAX_FC_DOMAINS; i++) {
      if((hash->domainStats[i].sentBytes.value != 0) ||
	 (hash->domainStats[i].rcvdBytes.value != 0)) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf), "<TR "TR_ON" %s><TD "TD_BG" align=right>%x</td>"
		      "<TD "TD_BG" align=right>%s</TD><TD "TD_BG" align=right>%s</TD>"
		      "<TD "TD_BG" align=right>%s</TD><TD "TD_BG" align=right>%s</TD>",
		      getRowColor(), i, "N/A", "N/A",
		      formatBytes (hash->domainStats[i].sentBytes.value, 1,
				   formatBuf, sizeof (formatBuf)),
		      formatBytes (hash->domainStats[i].rcvdBytes.value, 1,
				   formatBuf1, sizeof (formatBuf1))
		      );
	sendString (buf);

      }
    }
  }

  sendString("</TD></TR>\n");
  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</TABLE>"TABLE_OFF"<P>\n");


  /* **************************** */
  printSectionTitle("Top Domain Traffic Distribution (Sent)");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
                "<iframe frameborder=0 SRC=" CONST_BAR_VSAN_TRAF_DIST_SENT "-%d"CHART_FORMAT"?1 "
		"ALT=\"VSAN Domain Traffic Distribution for VSAN %d\" width=400 height=250></iframe></TH></TR>",
                vsanId, vsanId);
  sendString(buf);

  printSectionTitle("Top Domain Traffic Distribution (Received)");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		"<iframe frameborder=0 SRC=" CONST_BAR_VSAN_TRAF_DIST_RCVD "-%d"CHART_FORMAT"?1 "
		"ALT=\"VSAN Domain Traffic Distribution for VSAN %d\" width=400 height=250></iframe></TH></TR>",
                vsanId, vsanId);
  sendString(buf);

  printVsanProtocolStats (hash, actualDeviceId);

#ifdef NOT_YET
  printFcTrafficMatrix (vsanId, TRUE);

  printSectionTitle("Control Traffic Distribution");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
                "<iframe frameborder=0 SRC=" CONST_PIE_VSAN_CNTL_TRAF_DIST "-%d"CHART_FORMAT"?1 ALT=\"VSAN Control "
                "Traffic Protocol Distribution for VSAN %d\" width=400 height=250></iframe></TH></TR>",
                vsanId, vsanId);
  sendString(buf);
#endif

  sendString("</CENTER>\n");
}

/* ************************************ */

static char* formatFcElementData (FcFabricElementHash *hash, u_char printBytes, char *buf, int bufLen)
{
  char formatBuf[32];

  if((printBytes && (hash->totBytes.value == 0)) ||
     (!printBytes && (hash->totPkts.value == 0)))
    return("&nbsp;");

  if(printBytes) {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "%s",
		  formatBytes(hash->totBytes.value, 1, formatBuf,
			      sizeof (formatBuf)));
  }
  else {
    safe_snprintf(__FILE__, __LINE__, buf, bufLen, "%s",
		  formatPkts(hash->totPkts.value, formatBuf,
			     sizeof (formatBuf)));
  }

  return(buf);
}

/* ******************************** */

void dumpFcFabricElementHash (FcFabricElementHash **theHash, char* label,
                              u_char dumpLoopbackTraffic, u_char vsanHash) {
  u_char entries[MAX_HASHDUMP_ENTRY];
  char buf[LEN_GENERAL_WORK_BUFFER], buf1[96], buf3[96],
    hostLinkBuf[LEN_GENERAL_WORK_BUFFER], formatBuf[32], vsanBuf[32];
  int i;
  HostTraffic *el;

  if(theHash == NULL) return;

  /* *********** */

#ifdef FC_DEBUG
  for(i=0; i<MAX_ELEMENT_HASH; i++)
    if(theHash[i] != NULL) {
      printf("[%d] ", theHash[i]->vsanId);
      hash = theHash[i]->next;

      while(hash != NULL) {
	printf("%d ", hash->vsanId);
	hash = hash->next;
      }

      printf("\n");
    }
#endif

  /* *********** */

  memset(entries, 0, sizeof(entries));

  for (i=0; i<MAX_ELEMENT_HASH; i++) {
    if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
       (theHash[i]->vsanId < MAX_USER_VSAN)) {
      if(theHash[i]->totPkts.value)
	entries[theHash[i]->vsanId] = 1;
    }
  }

  sendString("<CENTER><TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR><TH "DARK_BG">");
  sendString(label);

  sendString("</TH>\n<TH "DARK_BG">Principal Switch");
  sendString("</TH>\n<TH "DARK_BG">Total Traffic (Bytes)</TH>\n"
	     "<TH "DARK_BG">Total Traffic (Frames)</TH>\n");
  sendString("<TH "DARK_BG">Last Fabric Conf Time</TH>\n");
  if(vsanHash) sendString("<TH "DARK_BG">Nx_Ports</TH>\n");
  sendString("</TR>\n");

  /* ****************** */

  for(i=0; i<MAX_HASHDUMP_ENTRY; i++) {
    if(entries[i] == 1) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR><TH "TH_BG" ALIGN=LEFT NOWRAP>%s\">%d</a></TH>\n"
		    "<TD>%s</TD>\n<TD>%s</TD>\n<TD>%s</TD>\n<TD>%s</TD>\n",
		    makeVsanLink (i, FLAG_HOSTLINK_TEXT_FORMAT, vsanBuf, sizeof (vsanBuf)), i,
		    fcwwn_to_str ((u_int8_t *)&theHash[i]->principalSwitch.str),
		    formatFcElementData(theHash[i], 1, buf1, sizeof(buf1)),
		    formatFcElementData(theHash[i], 0, buf3, sizeof(buf3)),
		    formatTime(&theHash[i]->fabricConfStartTime,
			       formatBuf, sizeof (formatBuf)));
      sendString(buf);


      sendString("<TD>&nbsp;");
      if(vsanHash) {
	int iEntryCount=0;

	for(el = getFirstHost(myGlobals.actualReportDeviceId);
	    el != NULL; el = getNextHost (myGlobals.actualReportDeviceId, el)) {
	  if((el->fcCounters->vsanId == i) && isValidFcNxPort (&el->fcCounters->hostFcAddress) &&
	     (el->fcCounters->fcBytesSent.value || el->fcCounters->fcBytesRcvd.value)) {
	    if(++iEntryCount == 1) sendString("<ul>");
	    sendString("<li>");
	    sendString (makeFcHostLink (el,
					FLAG_HOSTLINK_TEXT_FORMAT,
					0, 0, hostLinkBuf,
					sizeof(hostLinkBuf)));
	    sendString("</li>\n");
	  }
	}
	if(iEntryCount > 0) sendString("</ul>\n");
      }

      sendString("</TD>\n</TR>\n");
    }
  }

  sendString("</TR>\n</TABLE>\n</CENTER>\n");
}

/* ************************************ */

void printFcDisplayOptions (void)
{
  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("FC Host Display Options ", 0, 0);
}

/* ******************************************************** */

void printVsanProtocolStats (FcFabricElementHash *hash, int actualDeviceId)
{
  Counter total;
  char buf[LEN_GENERAL_WORK_BUFFER];

  if(hash == NULL) {
    return;
  }

  if((total = hash->totBytes.value) == 0) {
    return;
  }

  printSectionTitle("VSAN Protocol Distribution");

  sendString("<CENTER>\n"
	     ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR><TH "TH_BG" WIDTH=100 "DARK_BG">Protocol</TH>"
	     "<TH "TH_BG" WIDTH=200 COLSPAN=3 "DARK_BG">Total&nbsp;Bytes</TH></TR>\n");

  if(hash->fcFcpBytes.value) {
    printTableEntry(buf, sizeof(buf), "SCSI", CONST_COLOR_1,
		    (float)hash->fcFcpBytes.value/1024,
		    100*((float)SD(hash->fcFcpBytes.value, total)), 0, 0, 0);
  }

  if(hash->fcElsBytes.value) {
    printTableEntry(buf, sizeof(buf), "ELS", CONST_COLOR_1,
		    (float)hash->fcElsBytes.value/1024,
		    100*((float)SD(hash->fcElsBytes.value, total)), 0, 0, 0);
  }

  if(hash->fcDnsBytes.value) {
    printTableEntry(buf, sizeof (buf), "NS", CONST_COLOR_1,
		    (float)hash->fcDnsBytes.value/1024,
		    100*((float)SD(hash->fcDnsBytes.value, total)), 0, 0, 0);
  }

  if(hash->fcIpfcBytes.value) {
    printTableEntry(buf, sizeof (buf), "IP/FC", CONST_COLOR_1,
		    (float)hash->fcIpfcBytes.value/1024,
		    100*((float)SD(hash->fcIpfcBytes.value, total)), 0, 0, 0);
  }

  if(hash->fcSwilsBytes.value) {
    printTableEntry(buf, sizeof (buf), "SWILS", CONST_COLOR_1,
		    (float)hash->fcSwilsBytes.value/1024,
		    100*((float)SD(hash->fcSwilsBytes.value, total)), 0, 0, 0);
  }

  if(hash->otherFcBytes.value) {
    printTableEntry(buf, sizeof (buf), "Others", CONST_COLOR_1,
		    (float)hash->otherFcBytes.value/1024,
		    100*((float)SD(hash->otherFcBytes.value, total)), 0, 0, 0);
  }

  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");
}

/* ******************************* */

void printFcHostsInfo(int sortedColumn, int revertOrder, int pageNum, int showBytes, int vsanId)
{
  u_int idx, numEntries, maxHosts;
  int printedEntries=0, i;
  unsigned short maxBandwidthUsage=1 /* avoid divisions by zero */;
  struct hostTraffic *el;
  struct hostTraffic** tmpTable;
  char buf[2*LEN_GENERAL_WORK_BUFFER], *arrowGif, *sign, *arrow[12], *theAnchor[12];
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER], formatBuf[32], hostLinkBuf[LEN_GENERAL_WORK_BUFFER];
  char htmlAnchor[64], htmlAnchor1[64], tmpbuf[LEN_FC_ADDRESS_DISPLAY];
  u_char *vsanList, foundVsan = 0, vsanStr[16];

  vsanList = calloc(1, MAX_USER_VSAN);
  if(vsanList == NULL) return;
  vsanId = abs(vsanId);

  printSectionTitle("FibreChannel Hosts Information");

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*), "printFcHostsInfo");
  if(tmpTable == NULL) {
    free (vsanList);
    return;
  }

  memset(buf, 0, sizeof(buf));

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  myGlobals.columnSort = sortedColumn;

  numEntries = 0;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    unsigned short actUsage, actUsageS, actUsageR;

    if (!isFcHost (el) || (el->fcCounters->vsanId > MAX_USER_VSAN)) continue;

    if (isValidVsanId (el->fcCounters->vsanId)) {
      vsanList[el->fcCounters->vsanId] = 1;
      foundVsan = 1;
    }

    if ((vsanId > 0) && (vsanId != el->fcCounters->vsanId)) continue;

    if((el->fcCounters->hostNumFcAddress[0] != '\0') &&
       el->fcCounters->fcBytesSent.value) {
      if(showBytes) {
	actUsage  = (unsigned short)(0.5+100.0*(((float)el->fcCounters->fcBytesSent.value+(float)el->fcCounters->fcBytesRcvd.value)/
						(float)myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value));
	actUsageS = (unsigned short)(0.5+100.0*((float)el->fcCounters->fcBytesSent.value/
						(float)myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value));
	actUsageR = (unsigned short)(0.5+100.0*((float)el->fcCounters->fcBytesRcvd.value/
						(float)myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value));
      } else {
	actUsage  = (unsigned short)(0.5+100.0*(((float)el->fcCounters->fcPktsSent.value+(float)el->fcCounters->fcPktsRcvd.value)/
						(float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value));
	actUsageS = (unsigned short)(0.5+100.0*((float)el->fcCounters->fcPktsSent.value/
						(float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value));
	actUsageR = (unsigned short)(0.5+100.0*((float)el->fcCounters->fcPktsRcvd.value/
						(float)myGlobals.device[myGlobals.actualReportDeviceId].fcPkts.value));
      }

      el->actBandwidthUsage = actUsage;
      if(el->actBandwidthUsage > maxBandwidthUsage)
	maxBandwidthUsage = actUsage;
      el->actBandwidthUsageS = actUsageS;
      el->actBandwidthUsageR = actUsageR;
    }

    tmpTable[numEntries++]=el;

    if(numEntries >= maxHosts)
      break;
  }

  if(numEntries <= 0) {
    printNoDataYet();
    free(vsanList);
    free(tmpTable);
    return;
  }

  qsort(tmpTable, numEntries, sizeof(struct hostTraffic*), sortHostFctn);

  safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s",
                CONST_FC_HOSTS_INFO_HTML, sign);
  safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=",
                CONST_FC_HOSTS_INFO_HTML);

  for(i=1; i<=9; i++) {
    if(abs(myGlobals.columnSort) == i) {
      arrow[i] = arrowGif;
      theAnchor[i] = htmlAnchor;
    } else {
      arrow[i] = "";
      theAnchor[i] = htmlAnchor1;
    }
  }

  if(abs(myGlobals.columnSort) == FLAG_DOMAIN_DUMMY_IDX) {
    arrow[0] = arrowGif;
    theAnchor[0] = htmlAnchor;
  } else {
    arrow[0] = "";
    theAnchor[0] = htmlAnchor1;
  }

  sendString("<P ALIGN=LEFT>");

  if(vsanId > 0)
    safe_snprintf(__FILE__, __LINE__, (char*)vsanStr, sizeof(vsanStr), "&VSAN=%d", vsanId);
  else
    vsanStr[0] = '\0';

  if(showBytes)
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<b>Traffic Unit:</b> [ <B>Bytes</B> ]&nbsp;"
		  "[ <A HREF=\"/%s?col=%d&unit=0%s\">Packets</A> ]&nbsp;</TD>",
		  CONST_FC_HOSTS_INFO_HTML, myGlobals.columnSort, vsanStr);
  else
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<b>Traffic Unit:</b> [ <A HREF=\"/%s?col=%d&unit=1%s\">Bytes</A> ]&nbsp;"
		  "[ <B>Packets</B> ]&nbsp;</TD>",
		  CONST_FC_HOSTS_INFO_HTML, myGlobals.columnSort, vsanStr);

  sendString(buf);
  sendString("</P>\n");

  if(foundVsan) {
    u_char found = 0;

    sendString("<p><b>VSAN</b>: ");

    for(i=0; i< MAX_USER_VSAN; i++)
      if(vsanList[i] == 1) {
	if(i == vsanId)
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <b>%d</b> ] ", i), found = 1;
	else
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"/%s?unit=%d&vsan=%d\">%d</A> ] ",
			CONST_FC_HOSTS_INFO_HTML, showBytes, i, i);

	sendString(buf);
      }

    if(!found)
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <b>All</b> ] ");
    else
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "[ <A HREF=\"/%s?unit=%d\">All</A> ] ",
		    CONST_FC_HOSTS_INFO_HTML, showBytes);

    sendString(buf);
  }

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON">"
		"<TH "TH_BG" "DARK_BG">%s3>VSAN%s</A></TH>"
		"<TH "TH_BG" "DARK_BG">%s1>FC_Port%s</A></TH>"
		"</TH><TH "TH_BG" "DARK_BG">%s2>FC&nbsp;Address%s</A></TH>\n"
		"<TH "TH_BG" "DARK_BG">%s4>Bandwidth%s</A></TH>"
		"<TH "TH_BG" "DARK_BG">Nw&nbsp;Board&nbsp;Vendor</TH>"
		"<TH "TH_BG" "DARK_BG">%s9>Age%s</A></TH>"
		"</TR>\n",
		theAnchor[3], arrow[3],
		theAnchor[1], arrow[1],
		theAnchor[2], arrow[2],
		theAnchor[4], arrow[4],
		theAnchor[9], arrow[9]
		);

  sendString(buf);

  for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {
    if(revertOrder)
      el = tmpTable[numEntries-idx-1];
    else
      el = tmpTable[idx];

    if(el != NULL) {
      char *tmpName1, *tmpName2;

      strncpy (tmpbuf, fc_to_str ((u_int8_t *)&el->fcCounters->hostFcAddress),
	       LEN_FC_ADDRESS_DISPLAY);
      tmpName1 = tmpbuf;

      if((tmpName1[0] == '\0') || (strcmp(tmpName1, "0.0.0.0") == 0))
	tmpName1 = myGlobals.separator;

      tmpName2 = getVendorInfo (&el->fcCounters->pWWN.str[2], 0);
      if(tmpName2[0] == '\0') {
	tmpName2 = "N/A";
      }
#ifdef FC_DEBUG
      traceEvent(CONST_TRACE_INFO, "FC_DEBUG: %s <=> %s [%s/%s]",
		 el->hostNumIpAddress, sniffedName,
		 el->hostResolvedName, el->hostNumIpAddress);
#endif

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>", getRowColor());
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		    makeVsanLink (el->fcCounters->vsanId, 0,
				  vsanBuf, sizeof (vsanBuf)));
      sendString (buf);

      sendString(makeFcHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0,
				hostLinkBuf, sizeof (hostLinkBuf)));

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>",
		    tmpName1);
      sendString(buf);

      printBar(buf, sizeof(buf), el->actBandwidthUsageS, el->actBandwidthUsageR, maxBandwidthUsage, 3);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT>%s</TD>", tmpName2);
      sendString(buf);

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=RIGHT NOWRAP>%s</A></TD>",
		    formatSeconds(el->lastSeen - el->firstSeen,
				  formatBuf, sizeof (formatBuf)));
      sendString(buf);

      sendString("</TR>\n");
      printedEntries++;

      /* Avoid huge tables */
      if(printedEntries > myGlobals.runningPref.maxNumLines)
	break;
    } else {
      traceEvent(CONST_TRACE_WARNING, "quicksort() problem!");
    }
  }
  sendString("</TABLE>"TABLE_OFF"<P>\n");
  sendString("</CENTER>\n");

  printFooterHostLink();

  printBandwidthFooter();

  addPageIndicator(CONST_HOSTS_INFO_HTML, pageNum, numEntries,
		   myGlobals.runningPref.maxNumLines, revertOrder,
		   abs(sortedColumn), -1);

  free(vsanList);
  free(tmpTable);
}

/* ************************************ */

void printFcAccounting(int remoteToLocal, int sortedColumn,
		       int revertOrder, int pageNum) {
  u_int idx, numEntries = 0, maxHosts, i;
  int printedEntries=0;
  HostTraffic *el, **tmpTable;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign;
  char tmpbuf[LEN_WWN_ADDRESS_DISPLAY+1];
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER], formatBuf[2][32];
  char hostLinkBuf[LEN_GENERAL_WORK_BUFFER];
  Counter totalBytesSent, totalBytesRcvd, totalBytes, a=0, b=0;
  float sentpct, rcvdpct;
  time_t timeDiff = time(NULL)-myGlobals.initialSniffTime;
  char *arrowGif, *arrow[8], *theAnchor[8];
  char htmlAnchor[64], htmlAnchor1[64];

  printSectionTitle("FibreChannel Per Port Traffic");

  maxHosts = myGlobals.device[myGlobals.actualReportDeviceId].hostsno; /* save it as it can change */

  tmpTable = (HostTraffic**)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].actualHashSize*sizeof(HostTraffic*), "printFcAccounting");
  if(tmpTable == NULL)
    return;

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  totalBytesSent=0, totalBytesRcvd=0;

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(!isFcHost (el)) continue;

    /* Skip Control VSAN traffic */
    if(el->fcCounters->vsanId > MAX_USER_VSAN) continue;

    if((el->fcCounters->fcBytesSent.value > 0) || (el->fcCounters->fcBytesRcvd.value > 0)) {
      tmpTable[numEntries++]=el;
      totalBytesSent += el->fcCounters->fcBytesSent.value;
      totalBytesRcvd += el->fcCounters->fcBytesRcvd.value;
    }
    if(numEntries >= maxHosts) break;
  }

  if(numEntries <= 0) {
    printNoDataYet();
    free(tmpTable);
    return;
  }

  myGlobals.columnSort = sortedColumn;
  qsort(tmpTable, numEntries, sizeof(struct hostTraffic*), cmpHostsFctn);

  safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
                "<a href=\"" CONST_FC_TRAFFIC_HTML "?col=%s", sign);
  safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
                "<a href=\"" CONST_FC_TRAFFIC_HTML "?col=");

  for (i = 1; i < 6; i++) {
    if(abs (myGlobals.columnSort) == i) {
      arrow[i] = arrowGif;
      theAnchor[i] = htmlAnchor;
    }
    else {
      arrow[i] = "";
      theAnchor[i] = htmlAnchor1;
    }
  }
  sendString("<CENTER>\n");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON">"
                "<TH "TH_BG" "DARK_BG">%s5\">VSAN%s</a></TH>"
                "<TH "TH_BG" "DARK_BG">%s1\">FC_Port%s</a></TH>"
                "<TH "TH_BG" "DARK_BG">%s2\">FC_ID%s</a></TH>\n"
                "<TH "TH_BG" COLSPAN=2 "DARK_BG">%s3\">Bytes&nbsp;Sent%s</a></TH>"
                "<TH "TH_BG" COLSPAN=2 "DARK_BG">%s4\">Bytes&nbsp;Rcvd%s</a></TH></TR>\n",
                theAnchor[5], arrow[5],
                theAnchor[1], arrow[1],
                theAnchor[2], arrow[2], theAnchor[3], arrow[3],
                theAnchor[4], arrow[4]);

  sendString(buf);

  for(idx=pageNum*myGlobals.runningPref.maxNumLines; idx<numEntries; idx++) {

    if(revertOrder)
      el = tmpTable[numEntries-idx-1];
    else
      el = tmpTable[idx];

    if(el != NULL) {
      char *tmpName1;
      strncpy (tmpbuf, (char *)el->fcCounters->hostNumFcAddress,
	       LEN_FC_ADDRESS_DISPLAY);
      tmpName1 = tmpbuf;

      a = el->fcCounters->fcBytesSent.value;
      b = el->fcCounters->fcBytesRcvd.value;

      if(a < 100)  /* Avoid very small decimal values */
	sentpct = 0;
      else
	sentpct = (100*(float)a)/totalBytesSent;

      if(b < 100)  /* Avoid very small decimal values */
	rcvdpct = 0;
      else
	rcvdpct = (100*(float)b)/totalBytesRcvd;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "%s"
		    "%s<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "</TD><TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD><TD "TD_BG" ALIGN=RIGHT>%.1f%s%%</TD></TR>\n",
		    getRowColor(),
		    makeVsanLink (el->fcCounters->vsanId, FLAG_HOSTLINK_HTML_FORMAT,
				  vsanBuf, sizeof (vsanBuf)),
		    makeFcHostLink(el, FLAG_HOSTLINK_HTML_FORMAT, 0, 0,
				   hostLinkBuf, sizeof (hostLinkBuf)),
		    tmpName1,
		    formatBytes(a, 1, formatBuf[0], 32),
		    sentpct, myGlobals.separator,
		    formatBytes(b, 1, formatBuf[1], 32),
		    rcvdpct, myGlobals.separator);
      sendString(buf);

      /* Avoid huge tables */
      if(printedEntries++ > myGlobals.runningPref.maxNumLines)
	break;
    }
  }

  sendString("</TABLE>"TABLE_OFF"\n");

  addPageIndicator(CONST_FC_TRAFFIC_HTML, pageNum, numEntries,
		   myGlobals.runningPref.maxNumLines,
		   revertOrder, abs(sortedColumn), -1);

  sendString("<P><CENTER>"TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR "TR_ON">"
	     "<TH "TH_BG" ALIGN=RIGHT "DARK_BG">Total Traffic</TH>"
	     "<TH "TH_BG" ALIGN=RIGHT "DARK_BG">Used Bandwidth</TH></TR>\n");

  totalBytes = totalBytesSent+totalBytesRcvd;

  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON">"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
                "<TD "TD_BG" ALIGN=RIGHT>%s</TD></TR>\n",
                formatBytes(totalBytes, 1, formatBuf[0], 32),
                formatThroughput((float)(totalBytes/timeDiff), 1,
                                 formatBuf[1], 32));

  sendString(buf);
  sendString("</TABLE>"TABLE_OFF"\n");
  sendString("</CENTER>\n");

  printFooterHostLink();

  free(tmpTable);
}

/* ********************************** */

int printScsiSessionBytes (int actualDeviceId, int sortedColumn, int revertOrder,
                           int pageNum, char *url, HostTraffic *el) {
  int idx, j, i;
  int numSessions, printedSessions, skipSessions;
  ScsiSessionSortEntry *tmpTable, *entry;
  FCSession *session;
  char buf[LEN_GENERAL_WORK_BUFFER*2], *sign;
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64];
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER], formatBuf[7][32];
  char hostLinkBuf[LEN_GENERAL_WORK_BUFFER],
    hostLinkBuf1[LEN_GENERAL_WORK_BUFFER];
  char pageUrl[64];

  printSectionTitle("SCSI Sessions");

  if(!myGlobals.runningPref.enableSessionHandling) {
    printNotAvailable("-z or --disable-sessions");
    return 0;
  }

  /* We have to allocate as many entries as there are sessions and LUNs
   * within a session.
   */
  tmpTable = (ScsiSessionSortEntry *) malloc (myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));
  if(tmpTable == NULL) {
    traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Unable to malloc sorting table\n");
    return 0;
  }

  memset (tmpTable, 0, myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));

  for(i=strlen(url); i>0; i--)
    if(url[i] == '?') {
      url[i] = '\0';
      break;
    }

  urlFixupToRFC1945Inplace(url);

  accessMutex(&myGlobals.fcSessionsMutex, "printScsiSessionBytes");

  /* Let's count sessions first */
  for (idx=1, numSessions=0; idx < MAX_TOT_NUM_SESSIONS; idx++) {
    session = myGlobals.device[myGlobals.actualReportDeviceId].fcSession[idx];
    while (session != NULL) {

      if(session->magic != CONST_MAGIC_NUMBER) {
	traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Invalid session magic\n");
	break;
      }
      if(session->fcpBytesSent.value || session->fcpBytesRcvd.value) {
	if((el && ((session->initiator  == el)
		   || (session->remotePeer == el)))
	   || (el == NULL)) {
	  for (j = 0; j < MAX_LUNS_SUPPORTED; j++) {
	    if(session->activeLuns[j] != NULL) {
	      if((session->activeLuns[j]->invalidLun &&
		  !myGlobals.runningPref.noInvalidLunDisplay) ||
		 (!session->activeLuns[j]->invalidLun)) {
		tmpTable[numSessions].initiator = session->initiator;
		tmpTable[numSessions].target = session->remotePeer;
		tmpTable[numSessions].lun = j;
		tmpTable[numSessions++].stats = session->activeLuns[j];
	      }
	      if(j > session->lunMax)
		break;
	    }
	  }
	  if((session->unknownLunBytesSent.value ||
	      session->unknownLunBytesRcvd.value)) {
	    if((el && ((session->initiator  == el)
		       || (session->remotePeer == el)))
	       || (el == NULL)) {
	      tmpTable[numSessions].initiator = session->initiator;
	      tmpTable[numSessions].target = session->remotePeer;
	      tmpTable[numSessions].lun = 0xFFFF;
	      tmpTable[numSessions++].stats = (ScsiLunTrafficInfo *)session;
	    }
	  }
	}
      }
      session = session->next;
    }
  }

  if(numSessions > 0) {

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
    } else {
      sign = "-";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
    }

    myGlobals.columnSort = sortedColumn;
    qsort (tmpTable, numSessions, sizeof (ScsiSessionSortEntry), cmpScsiSessionsFctn);

    if(el == NULL) {
      if(strcmp (url, CONST_SCSI_BYTES_HTML) == 0) {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s", url);
      }
      else {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s.html?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html", url);
      }
    }
    else {
      /* Need to add info about page in Hosts Info mode */
      safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=%s", url,
		    showHostScsiSessionBytes, pageNum, sign);
      safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=", url,
		    showHostScsiSessionBytes, pageNum);
      safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html?showF=%d",
		    url, showHostScsiSessionBytes);
    }

    for (i = 1; i < 48; i++) {

      if(abs(myGlobals.columnSort) == i) {
	arrow[i] = arrowGif;
	theAnchor[i] = htmlAnchor;
      } else {
	arrow[i] = "";
	theAnchor[i] = htmlAnchor1;
      }
    }
  }
  else {
    releaseMutex(&myGlobals.fcSessionsMutex);
    printNoDataYet ();
    free (tmpTable);
    return 0;
  }

  releaseMutex(&myGlobals.fcSessionsMutex);

  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */
  printedSessions = 0;
  skipSessions = 0;
  for (idx = 0; idx < numSessions; idx++) {
    Counter dataSent, dataRcvd;

    if(revertOrder)
      entry = &tmpTable[numSessions-idx-1];
    else
      entry = &tmpTable[idx];

    if(entry == NULL) {
      continue;
    }

    if(printedSessions < myGlobals.runningPref.maxNumLines) {

      if(el
	 && (entry->initiator  != el)
	 && (entry->target != el)) {
	continue;
      }

      if((skipSessions++) < pageNum*myGlobals.runningPref.maxNumLines) {
	continue;
      }

      if(printedSessions == 0) {
	sendString("<CENTER>\n");
	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%%\"><TR "TR_ON">"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s1>VSAN%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s2>Initiator%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s3>Target%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>LUN</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Total&nbsp;Bytes</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=3>Data&nbsp;Bytes</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Rd&nbsp;Size(Blks)</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Wr&nbsp;Size(Blks)</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Xfer&nbsp;Rdy&nbsp;Size</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>IOPS</TH>"
		      "</TR>\n",
		      theAnchor[1], arrow[1],
		      theAnchor[2], arrow[2],
		      theAnchor[3], arrow[3]);
	sendString (buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      "<TR "TR_ON" %s>"
		      "<TH "TH_BG" "DARK_BG">%s4>Sent%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s5>Rcvd%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s6>Read%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s7>Write%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s8>Other%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s9>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s10>Max%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s11>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s12>Max%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s13>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s14>Max%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s15>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s16>Max%s</A></TH>"
		      "</TR>\n",
		      getRowColor(),
		      theAnchor[4], arrow[4],
		      theAnchor[5], arrow[5],
		      theAnchor[6], arrow[6],
		      theAnchor[7], arrow[7],
		      theAnchor[8], arrow[8],
		      theAnchor[9], arrow[9],
		      theAnchor[10], arrow[10],
		      theAnchor[11], arrow[11],
		      theAnchor[12], arrow[12],
		      theAnchor[13], arrow[13],
		      theAnchor[14], arrow[14],
		      theAnchor[15], arrow[15],
		      theAnchor[16], arrow[16]);

	sendString(buf);

      }

      if(entry->lun != 0xFFFF) {
	dataSent = entry->stats->bytesSent.value;
	dataRcvd = entry->stats->bytesRcvd.value;

	/* Sanity check */
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%.1f</TD>"
		      "</TR>\n",
		      getRowColor(),
		      makeVsanLink (entry->initiator->fcCounters->vsanId, 0, vsanBuf,
				    sizeof (vsanBuf)),
		      makeFcHostLink(entry->initiator,
				     FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				     hostLinkBuf, sizeof (hostLinkBuf)),
		      makeFcHostLink(entry->target,
				     FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				     hostLinkBuf1, sizeof (hostLinkBuf1)),
		      entry->lun,
		      formatBytes(dataSent, 1, formatBuf[0], 32),
		      formatBytes(dataRcvd, 1, formatBuf[1], 32),
		      formatBytes (entry->stats->scsiRdBytes.value, 1,
				   formatBuf[2], 32),
		      formatBytes (entry->stats->scsiWrBytes.value, 1,
				   formatBuf[3], 32),
		      formatBytes (entry->stats->scsiOtBytes.value, 1,
				   formatBuf[4], 32),
		      entry->stats->minRdSize,
		      entry->stats->maxRdSize,
		      entry->stats->minWrSize,
		      entry->stats->maxWrSize,
		      formatBytes (entry->stats->minXferRdySize, 1,
				   formatBuf[5], 32),
		      formatBytes (entry->stats->maxXferRdySize, 1,
				   formatBuf[6], 32),
		      entry->stats->minIops,
		      entry->stats->maxIops
		      );
      }
      else {
	/* Unknown LUN data */
	session = (FCSession *)entry->stats;

	/* Sanity check */
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		      "</TR>\n",
		      getRowColor(),
		      makeVsanLink (entry->initiator->fcCounters->vsanId, 0, vsanBuf,
				    sizeof (vsanBuf)),
		      makeFcHostLink(entry->initiator,
				     FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				     hostLinkBuf, sizeof (hostLinkBuf)),
		      makeFcHostLink(entry->target,
				     FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				     hostLinkBuf1, sizeof (hostLinkBuf1)),
		      "N/A",
		      formatBytes(session->unknownLunBytesSent.value, 1,
				  formatBuf[0], 32),
		      formatBytes(session->unknownLunBytesRcvd.value, 1,
				  formatBuf[1], 32),
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A",
		      "N/A"
		      );
      }

      sendString(buf);
      printedSessions++;
    }
  }

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");
    sendString("<P><I>Note: Entries with LUN as N/A indicate traffic for which no command frame was seen</I></P>\n");
    addPageIndicator(pageUrl, pageNum, numSessions-1, myGlobals.runningPref.maxNumLines,
		     revertOrder, sortedColumn, -1);

    printFooterHostLink();
  } else {
    if(el == NULL) {
      printFlagedWarning("<I>No SCSI Sessions</I>");
    }
  }

  free (tmpTable);
  return (printedSessions);
}

/* ********************************** */

int printScsiSessionTimes (int actualDeviceId, int sortedColumn, int revertOrder,
                           int pageNum, char *url, HostTraffic *el) {
  int idx, j, i;
  int numSessions, printedSessions, skipSessions;
  ScsiSessionSortEntry *tmpTable, *entry;
  FCSession *session;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign;
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER], formatBuf[10][32];
  char hostLinkBuf[LEN_GENERAL_WORK_BUFFER],
    hostLinkBuf1[LEN_GENERAL_WORK_BUFFER];
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64], pageUrl[64];

  printSectionTitle("SCSI Sessions: Latencies");

  if(!myGlobals.runningPref.enableSessionHandling) {
    printNotAvailable("-z or --disable-sessions");
    return 0;
  }

  /* We have to allocate as many entries as there are sessions and LUNs
   * within a session.
   */
  tmpTable = (ScsiSessionSortEntry *) malloc (myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));
  if(tmpTable == NULL) {
    traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Unable to malloc sorting table\n");
    return 0;
  }

  memset (tmpTable, 0, myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));

  for(i=strlen(url); i>0; i--)
    if(url[i] == '?') {
      url[i] = '\0';
      break;
    }

  urlFixupFromRFC1945Inplace(url);

  accessMutex(&myGlobals.fcSessionsMutex, "printScsiSessionTimes");

  /* Let's count sessions first */
  for (idx=1, numSessions=0; idx < MAX_TOT_NUM_SESSIONS; idx++) {
    session = myGlobals.device[myGlobals.actualReportDeviceId].fcSession[idx];
    while (session != NULL) {
      if(session->magic != CONST_MAGIC_NUMBER) {
	traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Invalid session magic\n");
	break;
      }
      if(session->fcpBytesSent.value || session->fcpBytesRcvd.value) {
	if((el && ((session->initiator  == el)
		   || (session->remotePeer == el)))
	   || (el == NULL)) {
	  for (j = 0; j < MAX_LUNS_SUPPORTED; j++) {
	    if(session->activeLuns[j] != NULL) {
	      if((session->activeLuns[j]->invalidLun &&
		  !myGlobals.runningPref.noInvalidLunDisplay) ||
		 (!session->activeLuns[j]->invalidLun)) {
		tmpTable[numSessions].initiator = session->initiator;
		tmpTable[numSessions].target = session->remotePeer;
		tmpTable[numSessions].lun = j;
		tmpTable[numSessions++].stats = session->activeLuns[j];
	      }
	      if(j > session->lunMax)
		break;
	    }
	  }
	  /* Don't care about unknown LUN info as we don't gather
	   * anything but bytes for such traffic.
	   */
	}
      }
      session = session->next;
    }
  }

  if(numSessions > 0) {

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
    } else {
      sign = "-";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
    }

    myGlobals.columnSort = sortedColumn;
    qsort (tmpTable, numSessions, sizeof (ScsiSessionSortEntry), cmpScsiSessionsFctn);

    if(el == NULL) {
      if(strcmp (url, CONST_SCSI_TIMES_HTML) == 0) {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s", url);
      }
      else {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s.html?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html", url);
      }
    }
    else {
      /* Need to add info about page in Hosts Info mode */
      safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=%s", url,
		    showHostScsiSessionTimes, pageNum, sign);
      safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=", url,
		    showHostScsiSessionTimes, pageNum);
      safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html?showF=%d",
		    url, showHostScsiSessionTimes);
    }

    for (i = 1; i < 48; i++) {
      if(abs(myGlobals.columnSort) == i) {
	arrow[i] = arrowGif;
	theAnchor[i] = htmlAnchor;
      } else {
	arrow[i] = "";
	theAnchor[i] = htmlAnchor1;
      }
    }
  }
  else {
    releaseMutex(&myGlobals.fcSessionsMutex);
    printNoDataYet();
    free (tmpTable);
    return 0;
  }

  releaseMutex(&myGlobals.fcSessionsMutex);
  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */
  printedSessions = skipSessions = 0;
  for (idx = 0; idx < numSessions; idx++) {

    if(revertOrder)
      entry = &tmpTable[numSessions-idx-1];
    else
      entry = &tmpTable[idx];

    if(entry == NULL) {
      continue;
    }

    if(printedSessions < myGlobals.runningPref.maxNumLines) {

      if(el
	 && (entry->initiator  != el)
	 && (entry->target != el)) {
	continue;
      }

      if((skipSessions++) < pageNum*myGlobals.runningPref.maxNumLines) {
	continue;
      }

      if(printedSessions == 0) {
	sendString("<CENTER>\n");

	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%%\"><TR "TR_ON">"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s1>VSAN%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s2>Initiator%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s3>Target%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>LUN</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Cmd-Status&nbsp;RTT</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Cmd-XFR_RDY&nbsp;RTT</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Cmd-Data&nbsp;RTT(Rd)</TH>"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Cmd-Data&nbsp;RTT(Wr)</TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s26>Active&nbsp;Since%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s27>Last&nbsp;Seen%s</A></TH>"
		      "</TR>\n",
		      theAnchor[1], arrow[1],
		      theAnchor[2], arrow[2],
		      theAnchor[3], arrow[3],
		      theAnchor[26], arrow[26],
		      theAnchor[27], arrow[27]);
	sendString (buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      "<TR "TR_ON" %s>"
		      "<TH "TH_BG" "DARK_BG">%s18>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s19>Max%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s20>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s21>Max%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s22>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s23>Max%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s24>Min%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s25>Max%s</A></TH>"
		      "</TR>\n",
		      getRowColor(),
		      theAnchor[18], arrow[18],
		      theAnchor[19], arrow[19],
		      theAnchor[20], arrow[20],
		      theAnchor[21], arrow[21],
		      theAnchor[22], arrow[22],
		      theAnchor[23], arrow[23],
		      theAnchor[24], arrow[24],
		      theAnchor[25], arrow[25]);

	sendString(buf);

      }

      /* Sanity check */
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "</TR>\n",
		    getRowColor(),
		    makeVsanLink (entry->initiator->fcCounters->vsanId, 0,
				  vsanBuf, sizeof (vsanBuf)),
		    makeFcHostLink(entry->initiator,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof (hostLinkBuf)),
		    makeFcHostLink(entry->target,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf1, sizeof (hostLinkBuf1)),
		    entry->lun,
		    formatLatency (entry->stats->minRTT, FLAG_STATE_ACTIVE,
				   formatBuf[0], sizeof(formatBuf[0])),
		    formatLatency (entry->stats->maxRTT, FLAG_STATE_ACTIVE,
				   formatBuf[1], sizeof(formatBuf[1])),
		    formatLatency (entry->stats->minXfrRdyRTT, FLAG_STATE_ACTIVE,
				   formatBuf[2], sizeof(formatBuf[2])),
		    formatLatency (entry->stats->maxXfrRdyRTT, FLAG_STATE_ACTIVE,
				   formatBuf[3], sizeof(formatBuf[3])),
		    formatLatency (entry->stats->minRdFrstDataRTT, FLAG_STATE_ACTIVE,
				   formatBuf[4], sizeof(formatBuf[4])),
		    formatLatency (entry->stats->maxRdFrstDataRTT, FLAG_STATE_ACTIVE,
				   formatBuf[5], sizeof(formatBuf[5])),
		    formatLatency (entry->stats->minWrFrstDataRTT, FLAG_STATE_ACTIVE,
				   formatBuf[6], sizeof(formatBuf[6])),
		    formatLatency (entry->stats->maxWrFrstDataRTT, FLAG_STATE_ACTIVE,
				   formatBuf[7], sizeof(formatBuf[7])),
		    formatTime((time_t *)&(entry->stats->firstSeen),
			       formatBuf[8], sizeof(formatBuf[8])),
		    formatTime((time_t *)&(entry->stats->lastSeen),
			       formatBuf[9], sizeof(formatBuf[9]))
		    );

      sendString(buf);
      printedSessions++;
    }
  }

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    addPageIndicator(pageUrl, pageNum, numSessions, myGlobals.runningPref.maxNumLines,
		     revertOrder, sortedColumn, -1);

    printFooterHostLink();
  } else {
    if(el == NULL) {
      printFlagedWarning("<I>No SCSI Sessions</I>");
    }
  }

  free (tmpTable);
  return (printedSessions);
}

/* ********************************** */

int printScsiSessionStatusInfo(int actualDeviceId, int sortedColumn,
			       int revertOrder, int pageNum, char *url,
			       HostTraffic *el) {
  int idx, j, i;
  int numSessions, printedSessions, skipSessions;
  ScsiSessionSortEntry *tmpTable, *entry;
  FCSession *session;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign;
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64], pageUrl[64];
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER];
  char hostLinkBuf[LEN_GENERAL_WORK_BUFFER],
    hostLinkBuf1[LEN_GENERAL_WORK_BUFFER];

  printSectionTitle("SCSI Sessions: Status Info");

  if(!myGlobals.runningPref.enableSessionHandling) {
    printNotAvailable("-z or --disable-sessions");
    return 0;
  }

  /* We have to allocate as many entries as there are sessions and LUNs
   * within a session.
   */
  tmpTable = (ScsiSessionSortEntry *) malloc (myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));
  if(tmpTable == NULL) {
    traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Unable to malloc sorting table\n");
    return 0;
  }

  memset (tmpTable, 0, myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));

  for(i=strlen(url); i>0; i--)
    if(url[i] == '?') {
      url[i] = '\0';
      break;
    }

  urlFixupFromRFC1945Inplace(url);

  accessMutex(&myGlobals.fcSessionsMutex, "printScsiSessionStatusInfo");
  /* Let's count sessions first */
  for (idx=1, numSessions=0; idx < MAX_TOT_NUM_SESSIONS; idx++) {
    session = myGlobals.device[myGlobals.actualReportDeviceId].fcSession[idx];
    while (session != NULL) {
      if(session->magic != CONST_MAGIC_NUMBER) {
	traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Invalid session magic\n");
	break;
      }
      if(session->fcpBytesSent.value || session->fcpBytesRcvd.value) {
	if((el && ((session->initiator  == el)
		   || (session->remotePeer == el)))
	   || (el == NULL)) {
	  for (j = 0; j < MAX_LUNS_SUPPORTED; j++) {
	    if(session->activeLuns[j] != NULL) {
	      if((session->activeLuns[j]->invalidLun &&
		  !myGlobals.runningPref.noInvalidLunDisplay) ||
		 (!session->activeLuns[j]->invalidLun)) {
		tmpTable[numSessions].initiator = session->initiator;
		tmpTable[numSessions].target = session->remotePeer;
		tmpTable[numSessions].lun = j;
		tmpTable[numSessions++].stats = session->activeLuns[j];
	      }
	      if(j > session->lunMax)
		break;
	    }
	  }
	}
      }
      session = session->next;
    }
  }

  if(numSessions > 0) {

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
    } else {
      sign = "-";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
    }

    myGlobals.columnSort = sortedColumn;
    qsort (tmpTable, numSessions, sizeof (ScsiSessionSortEntry), cmpScsiSessionsFctn);

    if(el == NULL) {
      if(strcmp (url, CONST_SCSI_STATUS_HTML) == 0) {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s", url);
      }
      else {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s.html?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html", url);
      }
    }
    else {
      /* Need to add info about page in Hosts Info mode */
      safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=%s", url,
		    showHostScsiSessionStatus, pageNum, sign);
      safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=", url,
		    showHostScsiSessionStatus, pageNum);
      safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html?showF=%d",
		    url, showHostScsiSessionStatus);
    }

    for (i = 1; i < 48; i++) {
      if(abs(myGlobals.columnSort) == i) {
	arrow[i] = arrowGif;
	theAnchor[i] = htmlAnchor;
      } else {
	arrow[i] = "";
	theAnchor[i] = htmlAnchor1;
      }
    }
  }
  else {
    releaseMutex(&myGlobals.fcSessionsMutex);
    printNoDataYet();
    free (tmpTable);
    return 0;
  }
  releaseMutex(&myGlobals.fcSessionsMutex);
  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */
  printedSessions = skipSessions = 0;
  for (idx = 0; idx < numSessions; idx++) {

    if(revertOrder)
      entry = &tmpTable[numSessions-idx-1];
    else
      entry = &tmpTable[idx];

    if(entry == NULL) {
      continue;
    }

    if(printedSessions < myGlobals.runningPref.maxNumLines) {

      if(el
	 && (entry->initiator  != el)
	 && (entry->target != el)) {
	continue;
      }

      if((skipSessions++) < pageNum*myGlobals.runningPref.maxNumLines) {
	continue;
      }

      if(printedSessions == 0) {
	sendString("<CENTER>\n");
	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%%\"><TR "TR_ON">"
		      "<TH "TH_BG" "DARK_BG">%s1>VSAN%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s2>Initiator%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s3>Target%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">LUN</TH>"
		      "<TH "TH_BG" "DARK_BG">%s17>#&nbsp;Failed&nbsp;Cmds%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s28>#&nbsp;Check Condition%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s29>#&nbsp;Busy%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s30>#&nbsp;Reservation&nbsp;Conflict%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s31>#&nbsp;Task Set Full%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s32>#&nbsp;Task Aborts%s</A></TH>"
		      "</TR>\n",
		      theAnchor[1], arrow[1],
		      theAnchor[2], arrow[2],
		      theAnchor[3], arrow[3],
		      theAnchor[17], arrow[17],
		      theAnchor[28], arrow[28],
		      theAnchor[29], arrow[29],
		      theAnchor[30], arrow[30],
		      theAnchor[31], arrow[31],
		      theAnchor[32], arrow[32]);
	sendString (buf);
      }

      /* Sanity check */
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "</TR>\n",
		    getRowColor(),
		    makeVsanLink (entry->initiator->fcCounters->vsanId, 0, vsanBuf,
				  sizeof (vsanBuf)),
		    makeFcHostLink(entry->initiator,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof (hostLinkBuf)),
		    makeFcHostLink(entry->target,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf1, sizeof (hostLinkBuf1)),
		    entry->lun,
		    entry->stats->numFailedCmds,
		    entry->stats->chkCondCnt,
		    entry->stats->busyCnt,
		    entry->stats->resvConflictCnt,
		    entry->stats->taskSetFullCnt,
		    entry->stats->taskAbrtCnt);

      sendString(buf);
      printedSessions++;
    }
  }

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    addPageIndicator(pageUrl, pageNum, numSessions, myGlobals.runningPref.maxNumLines,
		     revertOrder, sortedColumn, -1);

    printFooterHostLink();
  } else {
    if(el == NULL) printFlagedWarning("<I>No SCSI Sessions</I>");
  }

  free (tmpTable);
  return (printedSessions);
}

/* ********************************** */

int printScsiSessionTmInfo (int actualDeviceId, int sortedColumn,
                            int revertOrder, int pageNum, char *url,
                            HostTraffic *el) {
  int idx, j, i;
  int numSessions, printedSessions, skipSessions;
  ScsiSessionSortEntry *tmpTable, *entry;
  FCSession *session;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign;
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64], pageUrl[64];
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER], formatBuf[2][32];
  char hostLinkBuf[LEN_GENERAL_WORK_BUFFER],
    hostLinkBuf1[LEN_GENERAL_WORK_BUFFER];

  printSectionTitle("SCSI Sessions: Task Management Info");

  if(!myGlobals.runningPref.enableSessionHandling) {
    printNotAvailable("-z or --disable-sessions");
    return 0;
  }

  /* We have to allocate as many entries as there are sessions and LUNs
   * within a session.
   */
  tmpTable = (ScsiSessionSortEntry *) malloc (myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));
  if(tmpTable == NULL) {
    traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Unable to malloc sorting table\n");
    return 0;
  }

  memset (tmpTable, 0, myGlobals.device[actualDeviceId].numFcSessions*MAX_LUNS_SUPPORTED*sizeof(ScsiSessionSortEntry));

  for(i=strlen(url); i>0; i--)
    if(url[i] == '?') {
      url[i] = '\0';
      break;
    }

  urlFixupFromRFC1945Inplace(url);

  accessMutex(&myGlobals.fcSessionsMutex, "printScsiSessionTmInfo");
  /* Let's count sessions first */
  for (idx=1, numSessions=0; idx < MAX_TOT_NUM_SESSIONS; idx++) {
    session = myGlobals.device[myGlobals.actualReportDeviceId].fcSession[idx];
    while (session != NULL) {
      if(session->magic != CONST_MAGIC_NUMBER) {
	traceEvent (CONST_TRACE_ERROR, "printScsiSessions: Invalid session magic\n");
	break;
      }

      if((session->fcpBytesRcvd.value) || (session->fcpBytesSent.value)) {
	if((el && ((session->initiator  == el)
		   || (session->remotePeer == el)))
	   || (el == NULL)) {
	  for (j = 0; j < MAX_LUNS_SUPPORTED; j++) {
	    if(session->activeLuns[j] != NULL) {
	      if((session->activeLuns[j]->invalidLun &&
		  !myGlobals.runningPref.noInvalidLunDisplay) ||
		 (!session->activeLuns[j]->invalidLun)) {
		tmpTable[numSessions].initiator = session->initiator;
		tmpTable[numSessions].target = session->remotePeer;
		tmpTable[numSessions].lun = j;
		tmpTable[numSessions++].stats = session->activeLuns[j];
	      }
	      if(j > session->lunMax)
		break;
	    }
	  }
	}
      }
      session = session->next;
    }
  }

  if(numSessions > 0) {

    if(revertOrder) {
      sign = "";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
    } else {
      sign = "-";
      arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
    }

    myGlobals.columnSort = sortedColumn;
    qsort (tmpTable, numSessions, sizeof (ScsiSessionSortEntry), cmpScsiSessionsFctn);

    if(el == NULL) {
      if(strcmp (url, CONST_SCSI_TM_HTML) == 0) {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s", url);
      }
      else {
	safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html?col=%s", url, sign);
	safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s.html?col=", url);
	safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html", url);
      }
    }
    else {
      /* Need to add info about page in Hosts Info mode */
      safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=%s", url,
		    showHostScsiSessionTMInfo, pageNum, sign);
      safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1),
		    "<A HREF=/%s.html?showF=%d&page=%d&col=", url,
		    showHostScsiSessionTMInfo, pageNum);
      safe_snprintf(__FILE__, __LINE__, pageUrl, sizeof (pageUrl), "%s.html?showF=%d",
		    url, showHostScsiSessionTMInfo);
    }

    for (i = 1; i < 48; i++) {
      if(abs(myGlobals.columnSort) == i) {
	arrow[i] = arrowGif;
	theAnchor[i] = htmlAnchor;
      } else {
	arrow[i] = "";
	theAnchor[i] = htmlAnchor1;
      }
    }
  } else {
    releaseMutex(&myGlobals.fcSessionsMutex);
    printNoDataYet();
    free (tmpTable);
    return 0;
  }

  releaseMutex(&myGlobals.fcSessionsMutex);
  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */
  printedSessions = skipSessions = 0;
  for (idx = 0; idx < numSessions; idx++) {

    if(revertOrder)
      entry = &tmpTable[numSessions-idx-1];
    else
      entry = &tmpTable[idx];

    if(entry == NULL) {
      continue;
    }

    if(printedSessions < myGlobals.runningPref.maxNumLines) {

      if(el
	 && (entry->initiator  != el)
	 && (entry->target != el)) {
	continue;
      }

      if((skipSessions++) < pageNum*myGlobals.runningPref.maxNumLines) {
	continue;
      }

      if(printedSessions == 0) {
	sendString("<CENTER>\n");
	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%%\"><TR "TR_ON">"
		      "<TH "TH_BG" "DARK_BG">%s1>VSAN%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s2>Initiator%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s3>Target%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">LUN</TH>",
		      theAnchor[1], arrow[1],
		      theAnchor[2], arrow[2],
		      theAnchor[3], arrow[3]);
	sendString (buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      "<TH "TH_BG" "DARK_BG">%s33>#&nbsp;Abort Task Set%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s34>#&nbsp;Clear Task Set%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s35>#&nbsp;Clear ACA%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s36>#&nbsp;Target Reset%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s37>#&nbsp;LUN Reset%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s38>Last Target Reset Time%s</A></TH>"
		      "<TH "TH_BG" "DARK_BG">%s39>Last LUN Reset Time%s</A></TH>"
		      "</TR>\n",
		      theAnchor[33], arrow[33],
		      theAnchor[34], arrow[34],
		      theAnchor[35], arrow[35],
		      theAnchor[36], arrow[36],
		      theAnchor[37], arrow[37],
		      theAnchor[38], arrow[38],
		      theAnchor[39], arrow[39]);
	sendString (buf);
      }

      /* Sanity check */
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%d</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "</TR>\n",
		    getRowColor(),
		    makeVsanLink (entry->initiator->fcCounters->vsanId, 0, vsanBuf,
				  sizeof (vsanBuf)),
		    makeFcHostLink(entry->initiator,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof (hostLinkBuf)),
		    makeFcHostLink(entry->target,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf1, sizeof (hostLinkBuf1)),
		    entry->lun,
		    entry->stats->abrtTaskSetCnt,
		    entry->stats->clearTaskSetCnt,
		    entry->stats->clearAcaCnt,
		    entry->stats->tgtRstCnt,
		    entry->stats->lunRstCnt,
		    formatTime((time_t *)&(entry->stats->lastTgtRstTime),
			       formatBuf[0], 32),
		    formatTime((time_t *)&(entry->stats->lastLunRstTime),
			       formatBuf[1], 32));

      sendString(buf);
      printedSessions++;
    }
  }

  if(printedSessions > 0) {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    addPageIndicator(pageUrl, pageNum, numSessions, myGlobals.runningPref.maxNumLines,
		     revertOrder, sortedColumn, -1);

    printFooterHostLink();
  } else {
    if(el == NULL) {
      printFlagedWarning("<I>No SCSI Sessions</I>");
    }
  }

  free (tmpTable);
  return (printedSessions);
}

/* ********************************** */

void printFCSessions (int actualDeviceId, int sortedColumn, int revertOrder,
                      int pageNum, char *url, HostTraffic *el) {
  int idx, i;
  int numSessions, printedSessions, skipSessions;
  unsigned long duration;
  char buf[LEN_GENERAL_WORK_BUFFER], *sign;
  char *arrowGif, *arrow[48], *theAnchor[48];
  char htmlAnchor[64], htmlAnchor1[64];
  char vsanBuf[LEN_MEDIUM_WORK_BUFFER], formatBuf[7][32];
  char hostLinkBuf[LEN_GENERAL_WORK_BUFFER],
    hostLinkBuf1[LEN_GENERAL_WORK_BUFFER];
  FCSession **tmpTable, *session;

  printSectionTitle("FibreChannel Sessions");

  if(!myGlobals.runningPref.enableSessionHandling) {
    printNotAvailable("-z or --disable-sessions");
    return;
  }

  tmpTable = (FCSession**)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].numFcSessions*sizeof(FCSession *), "printFCSessions");
  if(tmpTable == NULL)
    return;

  for(i=strlen(url); i>0; i--)
    if(url[i] == '?') {
      url[i] = '\0';
      break;
    }

  urlFixupFromRFC1945Inplace(url);

  /*
    Due to the way sessions are handled, sessions before those to
    display need to be skipped
  */

  accessMutex(&myGlobals.fcSessionsMutex, "printFCSessions");
  /* Let's count sessions first */
  for (idx=1, numSessions=0; idx < MAX_TOT_NUM_SESSIONS; idx++) {
    session = myGlobals.device[myGlobals.actualReportDeviceId].fcSession[idx];
    while (session != NULL) {
      if((session->bytesSent.value || session->bytesRcvd.value) &&
	 (session->initiator->fcCounters->vsanId < MAX_USER_VSAN)) {
	if((el
	    && ((session->initiator  == el)
		|| (session->remotePeer == el)))
	   || (el == NULL)) {
	  tmpTable[numSessions++] = session;
	}
      }
      session = session->next;
    }
  }

  releaseMutex(&myGlobals.fcSessionsMutex);

  if(numSessions <= 0) {
    printNoDataYet ();
    return;
  }

  if(revertOrder) {
    sign = "";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_UP;
  } else {
    sign = "-";
    arrowGif = "&nbsp;" CONST_IMG_ARROW_DOWN;
  }

  myGlobals.columnSort = sortedColumn;
  qsort (tmpTable, numSessions, sizeof (FCSession **), cmpFcSessionsFctn);

  if(strcmp (url, CONST_FC_SESSIONS_HTML) == 0) {
    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s?col=%s", url, sign);
    safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s?col=", url);
  } else {
    safe_snprintf(__FILE__, __LINE__, htmlAnchor, sizeof(htmlAnchor), "<A HREF=/%s.html?col=%s", url, sign);
    safe_snprintf(__FILE__, __LINE__, htmlAnchor1, sizeof(htmlAnchor1), "<A HREF=/%s.html?col=", url);
  }

  for (i = 1; i < 21; i++) {
    if(abs(myGlobals.columnSort) == i) {
      arrow[i] = arrowGif;
      theAnchor[i] = htmlAnchor;
    }
    else {
      arrow[i] = "";
      theAnchor[i] = htmlAnchor1;
    }
  }

  printedSessions = skipSessions = 0;
  for (idx = 0; idx < numSessions; idx++) {
    Counter dataSent, dataRcvd;

    if(revertOrder)
      session = tmpTable[numSessions-idx-1];
    else
      session = tmpTable[idx];

    if(session == NULL) {
      /* Some update is in progress ? */
      continue;
    }

    if(printedSessions < myGlobals.runningPref.maxNumLines) {

      if(el
	 && (session->initiator  != el)
	 && (session->remotePeer != el)) {
	continue;
      }

      if((skipSessions++) < pageNum*myGlobals.runningPref.maxNumLines) {
	continue;
      }

      if(printedSessions == 0) {
	sendString("<CENTER>\n");
	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=\"100%%\"><TR "TR_ON">"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s1>VSAN%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s2>Sender%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s3>Receiver%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Total</TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>SCSI</TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>ELS</TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>NS</TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>IP/FC</TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>SWILS</TH>\n"
		      "<TH "TH_BG" "DARK_BG" COLSPAN=2>Others</TH>\n"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s18>Active&nbsp;Since%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG" ROWSPAN=2>%s19>Last&nbsp;Seen%s</A></TH>"
		      "</TR>\n",
		      theAnchor[1], arrow[1],
		      theAnchor[2], arrow[2],
		      theAnchor[3], arrow[3],
		      theAnchor[18], arrow[18],
		      theAnchor[19], arrow[19]);
	sendString (buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      "<TR "TR_ON">"
		      "<TH "TH_BG" "DARK_BG">%s4>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s5>Rcvd%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s6>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s7>Rcvd%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s8>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s9>Rcvd%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s10>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s11>Rcvd%s</A></TH>\n",
		      theAnchor[4], arrow[4],
		      theAnchor[5], arrow[5],
		      theAnchor[6], arrow[6],
		      theAnchor[7], arrow[7],
		      theAnchor[8], arrow[8],
		      theAnchor[9], arrow[9],
		      theAnchor[10], arrow[10],
		      theAnchor[11], arrow[11]);
	sendString(buf);

	safe_snprintf(__FILE__, __LINE__, buf, sizeof (buf),
		      "<TH "TH_BG" "DARK_BG">%s12>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s13>Rcvd%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s14>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s15>Rcvd%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s16>Sent%s</A></TH>\n"
		      "<TH "TH_BG" "DARK_BG">%s17>Rcvd%s</A></TH>"
		      "</TR>\n",
		      theAnchor[12], arrow[12],
		      theAnchor[13], arrow[13],
		      theAnchor[14], arrow[14],
		      theAnchor[15], arrow[15],
		      theAnchor[16], arrow[16],
		      theAnchor[17], arrow[17]);
	sendString (buf);
      }

      dataSent = session->bytesSent.value;
      dataRcvd = session->bytesRcvd.value;
      duration = session->lastSeen.tv_sec - session->firstSeen.tv_sec;

      /* Sanity check */
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "<TD "TD_BG" ALIGN=RIGHT>%s</TD>"
		    "</TR>\n",
		    getRowColor(),
		    makeVsanLink (session->initiator->fcCounters->vsanId, 0,
				  vsanBuf, sizeof (vsanBuf)),
		    makeFcHostLink(session->initiator,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf, sizeof (hostLinkBuf)),
		    makeFcHostLink(session->remotePeer,
				   FLAG_HOSTLINK_TEXT_FORMAT, 0, 0,
				   hostLinkBuf1, sizeof (hostLinkBuf1)),
		    formatBytes(dataSent, 1, formatBuf[0], 32),
		    formatBytes(dataRcvd, 1, formatBuf[1], 32),
		    formatBytes(session->fcpBytesSent.value, 1,
				formatBuf[2], 32),
		    formatBytes(session->fcpBytesRcvd.value, 1,
				formatBuf[3], 32),
		    formatBytes(session->fcElsBytesSent.value, 1,
				formatBuf[4], 32),
		    formatBytes(session->fcElsBytesRcvd.value, 1,
				formatBuf[5], 32),
		    formatBytes(session->fcDnsBytesSent.value, 1,
				formatBuf[6], 32),
		    formatBytes(session->fcDnsBytesRcvd.value, 1,
				formatBuf[7], 32),
		    formatBytes(session->ipfcBytesSent.value, 1,
				formatBuf[8], 32),
		    formatBytes(session->ipfcBytesRcvd.value, 1,
				formatBuf[9], 32),
		    formatBytes(session->fcSwilsBytesSent.value, 1,
				formatBuf[10], 32),
		    formatBytes(session->fcSwilsBytesRcvd.value, 1,
				formatBuf[11], 32),
		    formatBytes(session->otherBytesSent.value, 1,
				formatBuf[12], 32),
		    formatBytes(session->otherBytesRcvd.value, 1,
				formatBuf[13], 32),
		    formatTime((time_t *)&(session->firstSeen),
			       formatBuf[14], 32),
		    formatTime((time_t *)&(session->lastSeen),
			       formatBuf[15], 32)
                    );

      sendString(buf);
      printedSessions++;
    }
  }

  if(printedSessions > 0)  {
    sendString("</TABLE>"TABLE_OFF"<P>\n");
    sendString("</CENTER>\n");

    addPageIndicator(url, pageNum, numSessions, myGlobals.runningPref.maxNumLines,
		     revertOrder, sortedColumn, -1);

    printFooterHostLink();
  } else {
    if(el == NULL) {
      printFlagedWarning("<I>No FibreChannel Sessions</I>");
    }
  }

  free (tmpTable);
}

/* ********************************** */

void printFcProtocolDistribution(int mode, int revertOrder, int printGraph)
{
  char buf[2*LEN_GENERAL_WORK_BUFFER], *sign;
  float total, partialTotal, remainingTraffic;
  float percentage;

  if(revertOrder)
    sign = "";
  else
    sign = "-";

  total = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcBytes.value;

  if(total == 0)
    return;
  else {

    int numProtosFound = 0;

    printSectionTitle("Global FibreChannel Protocol Distribution");

    sendString("<CENTER>\n");
    sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=660><TR "TR_ON"><TH "TH_BG" "DARK_BG" WIDTH=150>"
	       "FC&nbsp;Protocol</TH>"
	       "<TH "TH_BG" WIDTH=50 "DARK_BG">Total&nbsp;Bytes</TH><TH "TH_BG" COLSPAN=2 "DARK_BG">"
	       "Percentage</TH></TR>\n");

    remainingTraffic = 0;

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcFcpBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "SCSI",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcFiconBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "FICON",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcElsBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "ELS",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcDnsBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "NS",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcIpfcBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "IP/FC",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcSwilsBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "SWILS",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    partialTotal  = (float)myGlobals.device[myGlobals.actualReportDeviceId].otherFcBytes.value;
    if(partialTotal > 0) {
      remainingTraffic += partialTotal;
      percentage = ((float)(partialTotal*100))/((float)total);
      numProtosFound++;
      printTableEntry(buf, sizeof(buf), "Others",
		      CONST_COLOR_1, partialTotal/1024, percentage, 0, 0, 0);
    }

    if ((numProtosFound > 0) && printGraph)
      sendString("<TR "TR_ON"><TD "TD_BG" COLSPAN=4 ALIGN=CENTER BGCOLOR=white>"
		 "<iframe frameborder=0 SRC=\"" CONST_BAR_FC_PROTO_DIST CHART_FORMAT "\" "
		 " class=tooltip alt=\"Global FC protocol distribution chart\""
		 "width=620 height=250></iframe></TD></TR>\n");
    sendString("</TABLE>"TABLE_OFF"<P>\n");

    /* *********************** */

    sendString("<p>Note:This report includes broadcast packets</p>\n");
    sendString("</CENTER>\n");
  }
}

/* ************************ */

#ifdef NOT_YET
void printFcTrafficMatrix (u_short vsanId, u_char sent)
{
  int i, j, numEntries=0, numConsecutiveEmptyCells;
  char buf[LEN_GENERAL_WORK_BUFFER];
  short *activeHosts;
  Counter minTraffic=(Counter)LONG_MAX, maxTraffic=0, avgTraffic;
  Counter avgTrafficLow, avgTrafficHigh, tmpCounter;
  TrafficEntry *entry;

  if(myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrix == NULL) {
    printFlagedWarning("<I>Traffic matrix is not available for the selected network interface</I>");
    return;
  }

  /* Print a matrix, using just what the row/column header says: From -> To */
  /* This is different from IP which prints a total */
  if(vsanId) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "FibreChannel Traffic Matrix For VSAN %d", vsanId);
  }
  else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "FibreChannel Traffic Matrix For VSAN");
  }

  printSectionTitle(buf);

  activeHosts = (short*)mallocAndInitWithReportWarn(myGlobals.device[myGlobals.actualReportDeviceId].numHosts*sizeof(short), "printFcTrafficMatrix");
  if(activeHosts == NULL)
    return;

  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++) {

    activeHosts[i] = 0;
    for(j=1; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; j++) {
      int id;

      id = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;
      entry = myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrix[id];

      if((i == j) && (myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrixHosts[i] != NULL) &&
	 (strncmp (myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrixHosts[i]->fcCounters->hostNumFcAddress,
		   "ff.ff.fd", sizeof ("ff.ff.fd")) != 0)) {
      }
      else if((entry != NULL) && (entry->fcCounters->vsanId == vsanId)) {
	if((entry->bytesSent.value) || (entry->bytesRcvd.value)) {
	  activeHosts[i] = 1;
	  numEntries++;
	  break;
	}
      }
    }

    /* Print column header if there is traffic sent from another host to this
     * host
     */
    if(activeHosts[i] == 1) {
      if(numEntries == 1) {
	sendString("<CENTER>\n");
	if(sent)
	  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON"><TH "TH_BG" ALIGN=LEFT><SMALL>&nbsp;F&nbsp;"
		     "&nbsp;&nbsp;To<br>&nbsp;r<br>&nbsp;o<br>&nbsp;m</SMALL></TH>\n");
	else
	  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS"><TR "TR_ON"><TH "TH_BG" ALIGN=LEFT><SMALL>&nbsp;B&nbsp;"
		     "&nbsp;&nbsp;From<br>&nbsp;y<br></SMALL></TH>\n");
      }

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TH "TH_BG" ALIGN=CENTER><SMALL>%s</SMALL></TH>",
		    getHostName(myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrixHosts[i], 1));
      sendString(buf);
    }
  }

  if(numEntries == 0) {
    printNoDataYet();
    free(activeHosts);
    return;
  } else
    sendString("</TR>\n");

  /* Determine Min & Max values */
  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; i++) {
    for(j=1; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts-1; j++) {
      int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;
      entry = myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrix[idx];

      if((entry != NULL) && (entry->fcCounters->vsanId == vsanId)) {
	if(sent && entry->bytesSent.value) {
	  if(minTraffic > entry->bytesSent.value)
	    minTraffic = entry->bytesSent.value;
	  if(maxTraffic < entry->bytesSent.value)
	    maxTraffic = entry->bytesSent.value;
	}
	else if(!sent && entry->bytesRcvd.value) {
	  if(minTraffic > entry->bytesRcvd.value)
	    minTraffic = entry->bytesRcvd.value;
	  if(maxTraffic < entry->bytesRcvd.value)
	    maxTraffic = entry->bytesRcvd.value;
	}
      }
    }
  }

  avgTraffic = (Counter)(((float)minTraffic+(float)maxTraffic)/2);
  avgTrafficLow  = (avgTraffic*15)/100; /* 15% of the average */
  avgTrafficHigh = 2*(maxTraffic/3);   /* 75% of max traffic */


  /* Print rows */
  for(i=1; i<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; i++)
    if(activeHosts[i] == 1) {
      numConsecutiveEmptyCells=0;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TR "TR_ON" %s><TH "TH_BG" ALIGN=LEFT><SMALL>%s</SMALL></TH>",
		    getRowColor(), makeFcHostLink(myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrixHosts[i],
						  FLAG_HOSTLINK_TEXT_FORMAT, 1, 1));
      sendString(buf);

      for(j=1; j<myGlobals.device[myGlobals.actualReportDeviceId].numHosts; j++) {
	int idx = i*myGlobals.device[myGlobals.actualReportDeviceId].numHosts+j;

        if((i == j) &&
	   (strncmp (myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrixHosts[i]->fcCounters->hostNumFcAddress,
                     "ff.ff.fd", sizeof ("ff.ff.fd")) != 0)) {
	  numConsecutiveEmptyCells++;
        }
	else if(activeHosts[j] == 1) {
	  if(myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrix[idx] == NULL)
	    numConsecutiveEmptyCells++;
	  else {
	    if(numConsecutiveEmptyCells > 0) {
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n",
			    numConsecutiveEmptyCells);
	      sendString(buf);
	      numConsecutiveEmptyCells = 0;
	    }

	    if(sent) {
	      tmpCounter = myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrix[idx]->bytesSent.value;
	    }
	    else {
	      tmpCounter = myGlobals.device[myGlobals.actualReportDeviceId].fcTrafficMatrix[idx]->bytesRcvd.value;
	    }
	    /* Fix below courtesy of Danijel Doriae <danijel.doric@industrogradnja.tel.hr> */
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" ALIGN=CENTER %s>"
			  "<SMALL>%s</SMALL></A></TH>\n",
			  calculateCellColor(tmpCounter, avgTrafficLow, avgTrafficHigh),
			  formatBytes(tmpCounter, 1));
	    sendString(buf);
	  }
	}
      }

      if(numConsecutiveEmptyCells > 0) {
	safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<TD "TD_BG" COLSPAN=%d>&nbsp;</TD>\n",
		      numConsecutiveEmptyCells);
	sendString(buf);
	numConsecutiveEmptyCells = 0;
      }

      sendString("</TR>\n");
    }

  sendString("</TABLE>"TABLE_OFF"\n<P>\n");
  sendString("</CENTER>\n");

  printFooterHostLink();

  free(activeHosts);
}
#endif

/* ******************************************* */

void printVSANList(unsigned int deviceId) {
  printSectionTitle("VSAN Traffic Statistics");

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  } else if(myGlobals.device[deviceId].vsanHash == NULL) {
    printFlagedWarning("<I>No VSAN Traffic Information Available (yet).</I>");
    return;
  }

  dumpFcFabricElementHash(myGlobals.device[deviceId].vsanHash, "VSAN", 0, 1);
}

/* ********************************** */

void drawVsanStatsGraph (unsigned int deviceId)
{
  char buf[LEN_GENERAL_WORK_BUFFER], vsanBuf[LEN_MEDIUM_WORK_BUFFER];
  FcFabricElementHash **theHash;
  FcFabricElementHash *tmpTable[MAX_ELEMENT_HASH];
  int i, numVsans, j;
  char vsanLabel[LEN_GENERAL_WORK_BUFFER];

  if(deviceId > myGlobals.numDevices) {
    printFlagedWarning("<I>Invalid device specified</I>");
    return;
  } else if((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
    printSectionTitle("VSAN Summary");
    printNoDataYet();
    return;
  }

  printSectionTitle("Top 10 VSANs");

  numVsans = 0;
  memset (tmpTable, 0, sizeof (FcFabricElementHash *)*MAX_ELEMENT_HASH);

  for (i=0; i<MAX_ELEMENT_HASH; i++) {
    if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
       (theHash[i]->vsanId < MAX_USER_VSAN)) {
      if(theHash[i]->totBytes.value)
	tmpTable[numVsans++] = theHash[i];
    }
  }

  myGlobals.columnSort = 3;
  qsort (tmpTable, numVsans, sizeof (FcFabricElementHash **), cmpVsanFctn);

  sendString("<CENTER>\n");
  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=600><TR "TR_ON"><TH "TH_BG" "DARK_BG" WIDTH=25>"
	     "VSAN</TH>"
	     "<TH "TH_BG" "DARK_BG" WIDTH=75>Total&nbsp;Bytes</TH><TH "TH_BG" "DARK_BG" WIDTH=500 COLSPAN=2>"
	     "Percentage</TH></TR>\n");


  for (i = numVsans-1, j = 0; i >= 0; i--, j++) {
    if(tmpTable[i] != NULL) {
      safe_snprintf(__FILE__, __LINE__, vsanLabel, sizeof (vsanLabel), "%s",
		    makeVsanLink (tmpTable[i]->vsanId, 0, vsanBuf, sizeof (vsanBuf)));
      printTableEntry(buf, sizeof (buf), vsanLabel, CONST_COLOR_1,
		      (float) tmpTable[i]->totBytes.value/1024,
		      100*((float)SD(tmpTable[i]->totBytes.value,
				     myGlobals.device[deviceId].fcBytes.value)), 0, 0, 0);

    }

    if(j >= MAX_VSANS_GRAPHED)
      break;
  }
  sendString("</TABLE>"TABLE_OFF"<P>\n");

  printSectionTitle ("VSAN Traffic (Bytes)");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                "<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
                "<iframe frameborder=0 SRC=drawVsanStatsBytesDistribution"CHART_FORMAT"?1 ALT=\"VSAN Bytes Statistics "
                "VSAN Traffic (Total Bytes)\" width=650 height=250></iframe></TH></TR>" );
  sendString(buf);

  printSectionTitle ("VSAN Traffic (Frames)");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		"<TR "TR_ON" BGCOLOR=white><TH BGCOLOR=white ALIGN=CENTER COLSPAN=3>"
		"<iframe frameborder=0 SRC=drawVsanStatsPktsDistribution"CHART_FORMAT"?1 ALT=\"VSAN Frames Statistics "
		"VSAN Traffic (Total Frames)\" width=650 height=250></iframe></TH></TR>");
  sendString(buf);
}

/* ******************************************* */

void printFcTrafficSummary (u_short vsanId)
{
  int deviceId = myGlobals.actualReportDeviceId;
  char buf[LEN_GENERAL_WORK_BUFFER], vsanBuf[LEN_MEDIUM_WORK_BUFFER];
  FcFabricElementHash **theHash;
  FcFabricElementHash *tmpTable[MAX_ELEMENT_HASH];
  int i, numVsans, j;
  char vsanLabel[LEN_GENERAL_WORK_BUFFER];

  if((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
    return;
  }

  numVsans = 0;
  memset (tmpTable, 0, sizeof (FcFabricElementHash *)*MAX_ELEMENT_HASH);

  for (i=0; i<MAX_ELEMENT_HASH; i++) {
    if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
       (theHash[i]->vsanId < MAX_USER_VSAN)) {
      if(theHash[i]->totBytes.value)
	tmpTable[numVsans++] = theHash[i];
    }
  }

  myGlobals.columnSort = 3;
  qsort (tmpTable, numVsans, sizeof (FcFabricElementHash **), cmpVsanFctn);

  sendString("<P ALIGN=LEFT>");
  sendString(""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS" WIDTH=225><CAPTION><B>Top 10 VSANS</B></CAPTION><TR "TR_ON"><TH "TH_BG" "DARK_BG" WIDTH=10>"
	     "VSAN</TH>"
	     "<TH "TH_BG" "DARK_BG" WIDTH=15>Total&nbsp;Bytes</TH><TH "TH_BG" "DARK_BG" WIDTH=200 COLSPAN=2>"
	     "Percentage</TH></TR>\n");


  for (i = numVsans-1, j = 0; i >= 0; i--, j++) {
    if(tmpTable[i] != NULL) {
      safe_snprintf(__FILE__, __LINE__, vsanLabel, sizeof (vsanLabel), "%s",
		    makeVsanLink (tmpTable[i]->vsanId, 0, vsanBuf, sizeof (vsanBuf)));
      printTableEntry(buf, sizeof (buf), vsanLabel, CONST_COLOR_1,
		      (float) tmpTable[i]->totBytes.value/1024,
		      100*((float)SD(tmpTable[i]->totBytes.value,
				     myGlobals.device[deviceId].fcBytes.value)), 0, 0, 0);

    }

    if(j >= MAX_VSANS_GRAPHED)
      break;
  }
  sendString("</TABLE>"TABLE_OFF"<P>\n");
}
