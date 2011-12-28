/*
 *  Copyright (C) 1998-2011 Luca Deri <deri@ntop.org>
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

/*
 * Do not use local defs for pnggraph
 * (included by ntop.h)
 */

#include "ntop.h"

#define _GRAPH_C_
#include "globals-report.h"

/* ************************ */

struct bar_elements {
  char *label;
  float data;
};

/* ******************************************************************* */

static void send_graph_header(char *title) {
  sendString("<HTML>\n"
	     "<HEAD>\n"
	     "<TITLE>ntop chart</TITLE>\n"
	     "<META HTTP-EQUIV=REFRESH CONTENT=60>\n"
	     "<META HTTP-EQUIV=Pragma CONTENT=no-cache>\n"
	     "<META HTTP-EQUIV=Cache-Control CONTENT=no-cache>\n");

  sendJSLibraries(1);

  sendString("<script type=\"text/javascript\">\n");
  sendString("     var chart;\n");
  sendString("  $(document).ready(function() {\n");
  sendString("      chart = new Highcharts.Chart({\n");
  sendString("	chart: {\n");
  sendString("	  renderTo: 'container',\n");
  sendString("	      plotBackgroundColor: null,\n");
  sendString("	      plotBorderWidth: null,\n");
  sendString("	      plotShadow: false\n");
  sendString("	      },\n");
  sendString("	    title: {\n");
  sendString("	  text: '");
  sendString(title);
  sendString("'\n");
  sendString("	      },\n");
  sendString("	    tooltip: {\n");
  sendString("	  formatter: function() {\n");
  sendString("	      return '<b>'+ this.point.name +'</b>: '+ this.percentage +' %';\n");
  sendString("	    }\n");
  sendString("	  },\n");
  sendString("	    plotOptions: {\n");
  sendString("	  pie: {\n");
  sendString("	    allowPointSelect: true,\n");
  sendString("		cursor: 'pointer',\n");
  sendString("		dataLabels: {\n");
  sendString("	            enabled: true,\n");
  sendString("	        },\n");
  sendString("		showInLegend: true\n");
  sendString("	      }\n");
  sendString("	  },\n");
  sendString("	    series: [{\n");
  sendString("	    type: 'pie',\n");
  sendString("		name: '");
  sendString(title);
  sendString("',\n");
  sendString("		data: [\n");  
}

/**********************************************************/

static void send_graph_footer(void) {
  sendString("		       ]\n");
  sendString("		}]\n");
  sendString("	    });\n");
  sendString("    });\n");
  sendString("  </script>\n");

  sendString("<div id=\"container\" style=\"width: 350px; height: 320px; margin: 0 auto\"></div>\n");
}

/**********************************************************/

static void build_pie(char *title,
		      int num, float *p, char **lbl) {
  int i, elems = 0;
  char buf[256];
  float tot = 0;

  if(num == 0) return;

  send_graph_header(title);

  for(i=0; i<num; i++) {
    if(p[i] > 0) {
      if(elems > 0)
	sendString(",\n");

      snprintf(buf, sizeof(buf), "\t\t\t['%s',   %.1f]",
	       lbl[i],
	       p[i]
	       //(i == (num-1)) ? (100-tot) : p[i]
	       );
      tot += p[i];
      sendString(buf);
      elems++;
    }
  }

  sendString("\n");
  send_graph_footer();
}

/* ******************************************************************* */

void hostTrafficDistrib(HostTraffic *theHost, short dataSent) {
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  TrafficCounter totTraffic;
  int idx = 0;
  ProtocolsList *protoList = myGlobals.ipProtosList;

  if(dataSent) {
    totTraffic.value = theHost->tcpSentLoc.value+theHost->tcpSentRem.value+
      theHost->udpSentLoc.value+theHost->udpSentRem.value+
      theHost->icmpSent.value+theHost->ipv6BytesSent.value+
      theHost->greSent.value+theHost->ipsecSent.value;

    if(theHost->nonIPTraffic != NULL)
      totTraffic.value += theHost->nonIPTraffic->stpSent.value+
	theHost->nonIPTraffic->arp_rarpSent.value+
	theHost->nonIPTraffic->netbiosSent.value+
	theHost->nonIPTraffic->otherSent.value;

    idx = 0;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL)
	totTraffic.value += theHost->ipProtosList[idx]->sent.value;
      idx++, protoList = protoList->next;
    }
  } else {
    totTraffic.value = theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value+
      theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value+
      theHost->icmpRcvd.value+theHost->ipv6BytesRcvd.value+
      theHost->greRcvd.value+theHost->ipsecRcvd.value;

    if(theHost->nonIPTraffic != NULL)
      totTraffic.value += theHost->nonIPTraffic->stpRcvd.value
	+theHost->nonIPTraffic->arp_rarpRcvd.value
	+theHost->nonIPTraffic->netbiosRcvd.value
	+theHost->nonIPTraffic->otherRcvd.value;

    idx = 0;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL)
	totTraffic.value += theHost->ipProtosList[idx]->rcvd.value;
      idx++, protoList = protoList->next;
    }
  }

  if(totTraffic.value > 0) {
    if(dataSent) {
      if(theHost->tcpSentLoc.value+theHost->tcpSentRem.value > 0) {
	p[num] = (float)((100*(theHost->tcpSentLoc.value+
			       theHost->tcpSentRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpSentLoc.value+theHost->udpSentRem.value > 0) {
	p[num] = (float)((100*(theHost->udpSentLoc.value+
			       theHost->udpSentRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpSent.value > 0) {
	p[num] = (float)((100*theHost->icmpSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }

      if(theHost->ipv6BytesSent.value > 0) {
	p[num] = (float)((100*theHost->ipv6BytesSent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

	if(theHost->greSent.value > 0) {
	  p[num] = (float)((100*theHost->greSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "GRE";
	}

	if(theHost->ipsecSent.value > 0) {
	  p[num] = (float)((100*theHost->ipsecSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPSEC";
	}

      if(theHost->nonIPTraffic != NULL) {
	if(theHost->nonIPTraffic->stpSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->stpSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
	}

	if(theHost->nonIPTraffic->arp_rarpSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->arp_rarpSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
	}

	if(theHost->nonIPTraffic->netbiosSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->netbiosSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "NetBios";
	}

	if(theHost->nonIPTraffic->otherSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->otherSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "Other";
	}
      }
    } else {
      if(theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value > 0) {
	p[num] = (float)((100*(theHost->tcpRcvdLoc.value+
			       theHost->tcpRcvdFromRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value > 0) {
	p[num] = (float)((100*(theHost->udpRcvdLoc.value+
			       theHost->udpRcvdFromRem.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpRcvd.value > 0) {
	p[num] = (float)((100*theHost->icmpRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }

      if(theHost->ipv6BytesRcvd.value > 0) {
	p[num] = (float)((100*theHost->ipv6BytesRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->greRcvd.value > 0) {
	p[num] = (float)((100*theHost->greRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "GRE";
      }

      if(theHost->ipsecRcvd.value > 0) {
	p[num] = (float)((100*theHost->ipsecRcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPSEC";
      }

      if(theHost->nonIPTraffic != NULL) {
	if(theHost->nonIPTraffic->stpRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->stpRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
	}

	if(theHost->nonIPTraffic->arp_rarpRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->arp_rarpRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
	}

	if(theHost->nonIPTraffic->netbiosRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->netbiosRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "NetBios";
	}

	if(theHost->nonIPTraffic->otherRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->otherRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "Other";
	}
      }
  }

    idx = 0; protoList = myGlobals.ipProtosList;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL) {
	if(dataSent) {
	  if(theHost->ipProtosList[idx]->sent.value > 0) {
	    p[num] = (float)((100*theHost->ipProtosList[idx]->sent.value)/totTraffic.value);
	    if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = protoList->protocolName;
	  }
	} else {
	  if(theHost->ipProtosList[idx]->rcvd.value > 0) {
	    p[num] = (float)((100*theHost->ipProtosList[idx]->rcvd.value)/totTraffic.value);
	    if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = protoList->protocolName;
	  }
	}
      }

      idx++, protoList = protoList->next;
    }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (1)");
      return; /* TODO: this has to be handled better */
    }

    if(num == 1) p[0] = 100; /* just to be safe */

    build_pie("Traffic Distribution", num, p, lbl);
  }
}

/* ******************************************************************* */

void drawDeviceServiceDistribution(void) {
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num = 0;
  Counter totTraffic = 0;
  int i;

  for(i=0; i<myGlobals.l7.numSupportedProtocols; i++)
    totTraffic += myGlobals.device[myGlobals.actualReportDeviceId].l7.protoTraffic[i];

  for(i=0; i<myGlobals.l7.numSupportedProtocols; i++) {
    float val;
    
    val = (float)myGlobals.device[myGlobals.actualReportDeviceId].l7.protoTraffic[i];
    if(val > 0) {
      val = (float)((val * 100) / totTraffic);
      p[num] = val, lbl[num] = getProtoName(i);
      num++;

      if(num == 20) break;
    }
  }
  
  if(num == 0) {
    traceEvent(CONST_TRACE_WARNING, "Graph failure (1)");
    return; /* TODO: this has to be handled better */
  }
  
  if(num == 1) p[0] = 100; /* just to be safe */
  
  build_pie("Service Distribution", num, p, lbl);
}

/* ************************ */

void hostFragmentDistrib(HostTraffic *theHost, short dataSent) {
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  TrafficCounter totTraffic;

  if(dataSent)
    totTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value+theHost->icmpFragmentsSent.value;
  else
    totTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value+theHost->icmpFragmentsRcvd.value;

  if(totTraffic.value > 0) {
    if(dataSent) {
      if(theHost->tcpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsSent.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsSent.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsSent.value > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsSent.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }
    } else {
      if(theHost->tcpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->tcpFragmentsRcvd.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "TCP";
      }

      if(theHost->udpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->udpFragmentsRcvd.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "UDP";
      }

      if(theHost->icmpFragmentsRcvd.value > 0) {
	p[num] = (float)((100*(theHost->icmpFragmentsRcvd.value))/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "ICMP";
      }
    }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (2)");
      return; /* TODO: this has to be handled better */
    }

    if(num == 1) p[0] = 100; /* just to be safe */

    build_pie("Fragment Distribution", num, p, lbl);
  }
}

/* ************************ */

void hostTimeTrafficDistribution(HostTraffic *theHost, short dataSent) {
  float p[24];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0, i;

  for(i=0; i<24; i++) {
    TrafficCounter traf;

    if(theHost->trafficDistribution) {
      if(dataSent)
	traf.value = theHost->trafficDistribution->last24HoursBytesSent[i].value;
      else
      traf.value = theHost->trafficDistribution->last24HoursBytesRcvd[i].value;
    } else
      traf.value = 0;

    if(traf.value > 0) {
      p[num] = (float)traf.value;
      switch(i) {
      case 0:
	lbl[num++] = "12-1AM";
	break;
      case 1:
	lbl[num++] = "1-2AM";
	break;
      case 2:
	lbl[num++] = "2-3AM";
	break;
      case 3:
	lbl[num++] = "3-4AM";
	break;
      case 4:
	lbl[num++] = "4-5AM";
	break;
      case 5:
	lbl[num++] = "5-6AM";
	break;
      case 6:
	lbl[num++] = "6-7AM";
	break;
      case 7:
	lbl[num++] = "7-8AM";
	break;
      case 8:
	lbl[num++] = "8-9AM";
	break;
      case 9:
	lbl[num++] = "9-10AM";
	break;
      case 10:
	lbl[num++] = "10-11AM";
	break;
      case 11:
	lbl[num++] = "11AM-12PM";
	break;
      case 12:
	lbl[num++] = "12-1PM";
	break;
      case 13:
	lbl[num++] = "1-2PM";
	break;
      case 14:
	lbl[num++] = "2-3PM";
	break;
      case 15:
	lbl[num++] = "3-4PM";
	break;
      case 16:
	lbl[num++] = "4-5PM";
	break;
      case 17:
	lbl[num++] = "5-6PM";
	break;
      case 18:
	lbl[num++] = "6-7PM";
	break;
      case 19:
	lbl[num++] = "7-8PM";
	break;
      case 20:
	lbl[num++] = "8-9PM";
	break;
      case 21:
	lbl[num++] = "9-10PM";
	break;
      case 22:
	lbl[num++] = "10-11PM";
	break;
      case 23:
	lbl[num++] = "11PM-12AM";
	break;
      }
    }
  }

  if(num == 0) {
    traceEvent(CONST_TRACE_WARNING, "Graph failure (2)");
    return; /* TODO: this has to be handled better */
  }

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie("Time Traffic Distribution", num, p, lbl);
}

/* ************************ */

void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent) {
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  TrafficCounter totFragmentedTraffic, totTraffic;

  if(dataSent) {
    totTraffic.value = theHost->ipv4BytesSent.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value
      +theHost->icmpFragmentsSent.value;
  } else {
    totTraffic.value = theHost->ipv4BytesRcvd.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value
      +theHost->icmpFragmentsRcvd.value;
  }

  if(totTraffic.value > 0) {
    p[num] = (float)((100*totFragmentedTraffic.value)/totTraffic.value);
    lbl[num++] = "Frag";

    p[num] = (float)(100-((float)(100*totFragmentedTraffic.value)/totTraffic.value));
    if(p[num] > 0) { lbl[num++] = "Non Frag"; }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (3)");
      return; /* TODO: this has to be handled better */
    }

    if(num == 1) p[0] = 100; /* just to be safe */
    build_pie("Fragmented Traffic", num, p, lbl);
  }
}

/* ********************************** */

void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent) {
  float p[MAX_NUM_PROTOS] = { 0 };
  char	*lbl[MAX_NUM_PROTOS] = { "" };
  int i, num=0;
  Counter sent, rcvd, traffic;

  sent = rcvd = 0;
  for(i=0; i<myGlobals.l7.numSupportedProtocols; i++)
    sent += theHost->l7.traffic[i].bytesSent, rcvd += theHost->l7.traffic[i].bytesRcvd;

  traffic = dataSent ? sent : rcvd;

  for(i=0; i<myGlobals.l7.numSupportedProtocols; i++) {
    Counter val = dataSent ? theHost->l7.traffic[i].bytesSent : theHost->l7.traffic[i].bytesRcvd;

    if(val > 0) {
      p[num] = (float)((100*val)/traffic);
      lbl[num++] = getProtoName(i);
    }

    if(num >= MAX_NUM_PROTOS) break; /* Too much stuff */
  }

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie("Application Traffic", num, p, lbl);
}

/* ********************************** */

void pktSizeDistribPie(void) {
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "", "" };
  int num=0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 256";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 512";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 1024";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 1518";
  };

#ifdef MAKE_WITH_JUMBO_FRAMES
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 2500";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 6500";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&lt;= 9000";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&gt; 9000";
  };
#else
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "&gt; 1518";
  };
#endif


  if(num == 1) p[0] = 100; /* just to be safe */

  build_pie("Packet Size Distribution", num, p, lbl);
}

/* ********************************** */

void pktTTLDistribPie(void) {
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "" };
  int num=0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo32.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "<= 32";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "33 - 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo96.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "65 - 96";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "97 - 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo160.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "129 - 160";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo192.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "161 - 192";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo224.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "193 - 224";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktTTLStats.upTo255.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ipPkts.value;
    lbl[num++] = "225 - 255";
  };

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie("TTL Distribution", num, p, lbl);
}

/* ************************ */

void ipProtoDistribPie(void) {
  float p[3];
  char	*lbl[] = { "Loc", "Rem->Loc", "Loc->Rem" };
  int num=0;

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.remote2local.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.remote2local.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Rem->Loc";
  }

  p[num] = (float)(myGlobals.device[myGlobals.actualReportDeviceId].tcpGlobalTrafficStats.local2remote.value+
		   myGlobals.device[myGlobals.actualReportDeviceId].udpGlobalTrafficStats.local2remote.value)/1024;
  if(p[num] > 0) {
    lbl[num++] = "Loc->Rem";
  }

  if(num == 1) p[0] = 100; /* just to be safe */

  build_pie("IP Distribution", num, p, lbl);
}

/* ************************ */

void interfaceTrafficPie(void) {
  float p[MAX_NUM_DEVICES];
  int i;
  TrafficCounter totPkts;
  char	*lbl[MAX_NUM_DEVICES];
  int myDevices=0;

  totPkts.value = 0;

  for(i=0; i<myGlobals.numDevices; i++) {
    p[i] = (float)myGlobals.device[i].ethernetPkts.value;
    totPkts.value += myGlobals.device[i].ethernetPkts.value;
  }

  if(totPkts.value == 0) {
    traceEvent(CONST_TRACE_WARNING, "interfaceTrafficPie: no interfaces to draw");
    return;
  }

  for(i=0; i<myGlobals.numDevices; i++) {
    if(myGlobals.device[i].activeDevice) {
      p[myDevices]   = (float)(100*(((float)p[i])/totPkts.value));
      lbl[myDevices] = myGlobals.device[i].humanFriendlyName;
      myDevices++;
    }
  }

  if(myDevices == 1)
    p[0] = 100; /* just to be safe */
  else if(myDevices == 0) {
    traceEvent(CONST_TRACE_WARNING, "interfaceTrafficPie: no interfaces to draw");
    return;
  }

  build_pie("Devices Distribution", myDevices, p, lbl);
}

/* ************************ */

void pktCastDistribPie(void) {
  float p[3];
  char	*lbl[] = { "", "", "" };
  int num=0;
  TrafficCounter unicastPkts;

  unicastPkts.value = myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value
    - myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value
    - myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value;

  if(unicastPkts.value > 0) {
    p[num] = (float)(100*unicastPkts.value)/(float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "Unicast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].broadcastPkts.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "Broadcast";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].multicastPkts.value > 0) {
    int i;

    p[num] = 100;
    for(i=0; i<num; i++)
      p[num] -= p[i];

    if(p[num] < 0) p[num] = 0;
    lbl[num++] = "Multicast";
  };

  build_pie("Packets Distribution", num, p, lbl);
}

/* ************************ */

void drawTrafficPie(void) {
  TrafficCounter ip;
  float p[2];
  char	*lbl[] = { "IP", "Non IP" };
  int num = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value == 0) return;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value;

  p[0] = (float)(ip.value*100/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value);
  num++;
  p[1] = 100-p[0];

  if(p[1] > 0)
    num++;

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie("IP vs non IP", num, p, lbl);
}

/* ************************ */

void drawGlobalProtoDistribution(void) {
  float p[256]; /* Fix courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
  char	*lbl[16];
  int idx = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value; lbl[idx] = "TCP";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value; lbl[idx] = "UDP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value; lbl[idx] = "ICMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value; lbl[idx] = "Other IP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value; lbl[idx] = "(R)ARP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipsecBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipsecBytes.value;lbl[idx] = "IPsec";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value; lbl[idx] = "NetBios"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].greBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].greBytes.value; lbl[idx] = "GRE"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value; lbl[idx] = "IPv6"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value; lbl[idx] = "STP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value > 0) {
    p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value; lbl[idx] = "Other"; idx++; }

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList) {
    ProtocolsList *protoList = myGlobals.ipProtosList;
    int idx1 = 0;

    while(protoList != NULL) {
      if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value > 0) {
	p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
	lbl[idx] = protoList->protocolName; idx++;
      }

      idx1++, protoList = protoList->next;
    }
  }


  {
    int i;
    float the_max = (float)0.1;

    for(i=0; i<idx; i++) the_max = max(the_max, p[i]);
    for(i=0; i<idx; i++) p[i]    = (p[i]*100)/the_max;
  }

  build_pie("Protocol Distribution", idx, p, lbl);
}

/* ************************ */

void drawGlobalIpProtoDistribution(void) {
  int i, idx=0, idx1 = 0, maxNumDisplayProto = 13;
  float p[256];
  char *lbl[256];
  ProtocolsList *protoList = myGlobals.ipProtosList;
  float total, partialTotal = 0;

  total = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv4Bytes.value
    + (float)myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList) {
    while(protoList != NULL) {
      if(total > (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value)
	total -= (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
      else
	total = 0;

      idx1++, protoList = protoList->next;
    }

    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].l7.protoTraffic[i];
      if((p[idx] > 0) && ((p[idx]*100/total) > 1 /* the proto is at least 1% */)) {
	partialTotal += p[idx];
	lbl[idx] = myGlobals.ipTrafficProtosNames[i];
	idx++;
      }

      if(idx >= maxNumDisplayProto) break;
    }
  }

  if(total == 0) total = 1;

  for(i=0; i<idx; i++) p[i] = (p[i] * 100)/total;

  build_pie("IP Distribution", idx, p, lbl);
}

/* ******************************** */

int drawHostsDistanceGraph(int checkOnly) {
  int i, j, numPoints=0;
  char  *lbls[32], labels[32][16];
  float graphData[60];
  HostTraffic *el;

  memset(graphData, 0, sizeof(graphData));

  for(i=0; i<=30; i++) {
    if(i == 0)
      safe_snprintf(__FILE__, __LINE__, labels[i], sizeof(labels[i]), "Local/Direct");
    else
      safe_snprintf(__FILE__, __LINE__, labels[i], sizeof(labels[i]), "%d Hops", i);
    lbls[i] = labels[i];
    graphData[i] = 0;
  }

  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(!subnetPseudoLocalHost(el)) {
      j = guessHops(el);
      if((j > 0) && (j <= 30)) {
	graphData[j]++;
	numPoints++;
      }
    }
  } /* for */

  if(checkOnly)
    return(numPoints);

  if(numPoints == 0) {
    lbls[numPoints] = "Unknown Host Distance";
    graphData[numPoints] = 1;
    numPoints++;
  } else if(numPoints == 1) {
    graphData[0]++;
  }

  build_pie("Hosts Distance", 30, graphData, lbls);

  return(numPoints);
}

/* ************************ */

void buildTalkersGraph(char **labels, HostTalkerSeries *talkers,
		      int num_talkers, int num_datapoints) {
  int i, j;

  sendString("<HTML>\n"
	     "<HEAD>\n"
	     "<META HTTP-EQUIV=REFRESH CONTENT=120>\n"
	     "<META HTTP-EQUIV=Pragma CONTENT=no-cache>\n"
	     "<META HTTP-EQUIV=Cache-Control CONTENT=no-cache>\n");

  sendJSLibraries(1);

  sendString("<script type=\"text/javascript\">\n");
  sendString("    var chart;\n");
  sendString("  $(document).ready(function() {\n");
  sendString("      chart = new Highcharts.Chart({\n");
  sendString("	chart: {\n");
  sendString("	  renderTo: 'container',\n");
  sendString("	      defaultSeriesType: 'bar'\n");
  sendString("	      },\n");
  sendString("	    title: {\n");
  sendString("	  text: 'Top Host Talkers'\n");
  sendString("	      },\n");
  sendString("	    xAxis: {\n");
  sendString("	  categories: [\n");

  for(i=0; i<num_datapoints; i++) {
    char buf[32];

    snprintf(buf, sizeof(buf), "'%u.'", i+1);
    if(i > 0) sendString(",");
    sendString(buf);
  }

  sendString("]\n");
  sendString("	      },\n");
  sendString("	    yAxis: {\n");
  sendString("	  min: 0,\n");
  sendString("	      title: {\n");
  sendString("	    text: 'Host Traffic %'\n");
  sendString("		},\n");
  sendString("	      stackLabels: {\n");
  sendString("	    enabled: true,\n");
  sendString("		style: {\n");
  sendString("	      fontWeight: 'bold',\n");
  sendString("		  color: (Highcharts.theme && Highcharts.theme.textColor) || 'gray'\n");
  sendString("		  }\n");
  sendString("	    }\n");
  sendString("	  },\n");

#if 0
  sendString("	    legend: {\n");
  sendString("	  align: 'right',\n");
  sendString("	      x: -100,\n");
  sendString("	      verticalAlign: 'top',\n");
  sendString("	      y: 20,\n");
  sendString("	      floating: true,\n");
  sendString("	      backgroundColor: (Highcharts.theme && Highcharts.theme.legendBackgroundColorSolid) || 'white',\n");
  sendString("	      borderColor: '#CCC',\n");
  sendString("	      borderWidth: 1,\n");
  sendString("	      shadow: false\n");
  sendString("	      },\n");
#endif

  sendString("	    tooltip: {\n");
  sendString("	  formatter: function() {\n");
#if 0
  sendString("	      return '<b>'+ this.x +'</b><br/>'+\n");
  sendString("		 this.series.name +': '+ this.y +'<br/>'+\n");
  sendString("		'Total: '+ this.point.stackTotal;\n");
#else
  sendString("        return ''+ this.series.name +': '+ Math.round(this.percentage) +'%';\n");
#endif
  sendString("	    }\n");
  sendString("	  },\n");
  sendString("	    plotOptions: {\n");
  sendString("	  series: {\n");
  sendString("	    stacking: 'percent',\n");
  sendString("		dataLabels: {\n");
  sendString("	      enabled: false,\n");
  sendString("		  color: (Highcharts.theme && Highcharts.theme.dataLabelsColor) || 'white'\n");
  sendString("		  }\n");
  sendString("	    }\n");
  sendString("	  },\n");
  sendString("	    series: [\n");

  for(i=0; i<num_talkers; i++) {
    HostTraffic *el, tmpEl;
    char buf[LEN_GENERAL_WORK_BUFFER], *c;

    el = quickHostLink(talkers[i].hostSerial, myGlobals.actualReportDeviceId, &tmpEl);
    
    if((el->hostResolvedNameType == FLAG_HOST_SYM_ADDR_TYPE_NONE)
       || (el->hostResolvedName[0] == '\0') /* Safety check */
       ) {
      /* Let's search name in cache */
      if(getHostNameFromCache(&el->hostIpAddress, el->hostResolvedName, sizeof(el->hostResolvedName)) != NULL) {
	el->hostResolvedNameType = FLAG_HOST_SYM_ADDR_TYPE_NAME;
      }
    }

    c = (el->hostResolvedName[0] != '\0') ? el->hostResolvedName : el->hostNumIpAddress;
    
    if(el->hostResolvedName[0] != '\0') {
      c = el->hostResolvedName, j = 0;

      while(c[j] != '\0') {
	if(c[j] == '.') {
	  c[j] = '\0';
	  break;
	}
	
	j++;
      }
    } else
      c = el->hostNumIpAddress;
    
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "\t\t{\n\t\tname: '%s',\n", c);
		  
    sendString(buf);

    sendString("\t\t\tdata: [\n");
    for(j=0; j<num_datapoints; j++) {

      if(j > 0) sendString(", ");
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%.0f", talkers[i].bps_series[j]);
      sendString(buf);
    }

    sendString("]\n\t\t},\n");
  }

  sendString("		       ]\n");
  sendString("	    });\n");
  sendString("    });\n");
  sendString("  </script>\n");

  sendString("<div id=\"container\" style=\"width: 100%; height: 100%; margin: 0 auto\"></div>\n");
}

/* ************************ */
