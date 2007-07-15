/*
 *  Copyright (C) 1998-2007 Luca Deri <deri@ntop.org>
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

static void send_graph_header(u_char is_pie) {
sendString("<HTML>\n"
"<HEAD>\n"
"<META HTTP-EQUIV=REFRESH CONTENT=30>\n"
"<META HTTP-EQUIV=Pragma CONTENT=no-cache>\n"
"<META HTTP-EQUIV=Cache-Control CONTENT=no-cache>\n"
"<script type=\"text/javascript\" src=\"/MochiKit/MochiKit.js\"></script>\n"
"<script type=\"text/javascript\" src=\"/PlotKit/excanvas.js\"></script>\n"
"<script type=\"text/javascript\" src=\"/PlotKit/Base.js\"></script>\n"
"<script type=\"text/javascript\" src=\"/PlotKit/Layout.js\"></script>\n"
"<script type=\"text/javascript\" src=\"/PlotKit/Canvas.js\"></script>\n"
"<script type=\"text/javascript\" src=\"/PlotKit/SweetCanvas.js\"></script>\n"
"<script type=\"text/javascript\" src=\"/PlotKit/EasyPlot.js\"></script>\n"
"<style type=\"text/css\">\n"
"body {\n"
	   "font-family: \"Lucida Grande\", \"Tahoma\", \"Verdana\", \"Sans\", \"sans-serif\";\n"
	   "font-size: 12px;\n"
"}\n"
"</style>\n"
"<script type=\"text/javascript\">\n"
"//<![CDATA[\n"
"function drawchart() {\n"
"   var hasCanvas = CanvasRenderer.isSupported();\n"
"\n"
"   var opts = {\n"
);

if(is_pie) sendString("   \"pieRadius\": 0.42,	  \n");

 sendString("    \"colorScheme\": PlotKit.Base.palette(PlotKit.Base.baseColors()[0]),\n");
 if(is_pie) sendString("   \"backgroundColor\": PlotKit.Base.baseColors()[0].lighterColorWithLevel(1),\n" );
 sendString("   \"xTicks\": [");
}
 
/**********************************************************/

static void send_graph_middle() {
sendString("]\n"
	     "   };\n"
	     "\n"
	     "   var data1 = [");

}

/**********************************************************/

static void send_graph_footer(char *the_type, u_int width, u_int height) {
  char buf[256];

  sendString("];\n"
	     "   \n"
	     "   if (hasCanvas) {\n"
	     "       var pie = new EasyPlot(\"");

sendString(the_type);
sendString("\", opts, $(\'canvas");
sendString(the_type);
sendString("\'), [data1]);\n"
	     "   }\n"
	     "}\n"
	     "\n"
	     "addLoadEvent(drawchart);\n"
	     "//]]>\n"
	     "</script>\n"
	     "</head>\n"
	     "<body>\n"
	     "<div id=\"canvas");
sendString(the_type);


 snprintf(buf, sizeof(buf), 
	  "\" width=\"%d\" height=\"%d\"></div>\n"
	  "</body>\n"
	  "</html>\n", 
	  width, height);

 sendString(buf);
}

/**********************************************************/

static void build_chart(u_char is_pie, char *the_type, int num, float *p, 
			char **lbl, u_int width, u_int height) {
  int i, num_printed;
  char buf[64];

  send_graph_header(is_pie);

  for(i=0, num_printed=0; i<num; i++) {
    if(p[i] > 0) {
      snprintf(buf, sizeof(buf), "%c\n\t{v:%d, label:\"%s\"}", (num_printed == 0) ? ' ' : ',', i, lbl[i]);
      sendString(buf);
      num_printed++;
    }
  }

  send_graph_middle();

  for(i=0, num_printed=0; i<num; i++) {
    if(p[i] > 0) {
      snprintf(buf, sizeof(buf), "%c [%d, %.1f]", (num_printed == 0) ? ' ' : ',', i, p[i]);
      sendString(buf);
      num_printed++;
    }
  }

  if((num_printed == 1) && (p[0] == 100)) {
	  /* Workaround for an Internet Explorer bug */
      sendString(", [1, 0.01]");
  }

  send_graph_footer(the_type, width, height);
}

#define build_pie(a, b, c) build_chart(1, "pie", a, b, c, 350, 200)
#define build_line(a, b, c) build_chart(0, "line", a, b, c, 600, 200)
#define build_bar(a, b, c) build_chart(0, "bar", a, b, c, 600, 200)

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
      theHost->icmpSent.value+theHost->ipv6Sent.value;
    
    if(theHost->nonIPTraffic != NULL)
      totTraffic.value += theHost->nonIPTraffic->stpSent.value+
	theHost->nonIPTraffic->ipxSent.value+theHost->nonIPTraffic->osiSent.value+
	theHost->nonIPTraffic->dlcSent.value+
	theHost->nonIPTraffic->arp_rarpSent.value+theHost->nonIPTraffic->decnetSent.value+
	theHost->nonIPTraffic->appletalkSent.value+
	theHost->nonIPTraffic->netbiosSent.value+theHost->nonIPTraffic->otherSent.value;

    idx = 0;
    while(protoList != NULL) {
      if(theHost->ipProtosList[idx] != NULL) 
	totTraffic.value += theHost->ipProtosList[idx]->sent.value;
      idx++, protoList = protoList->next;
    }
  } else {
    totTraffic.value = theHost->tcpRcvdLoc.value+theHost->tcpRcvdFromRem.value+
      theHost->udpRcvdLoc.value+theHost->udpRcvdFromRem.value+
      theHost->icmpRcvd.value+theHost->ipv6Rcvd.value;

    if(theHost->nonIPTraffic != NULL)
      totTraffic.value += theHost->nonIPTraffic->stpRcvd.value
	+theHost->nonIPTraffic->ipxRcvd.value+theHost->nonIPTraffic->osiRcvd.value+theHost->nonIPTraffic->dlcRcvd.value+
	theHost->nonIPTraffic->arp_rarpRcvd.value+theHost->nonIPTraffic->decnetRcvd.value+theHost->nonIPTraffic->appletalkRcvd.value+
	theHost->nonIPTraffic->netbiosRcvd.value+theHost->nonIPTraffic->otherRcvd.value;
    
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

      if(theHost->ipv6Sent.value > 0) {
	p[num] = (float)((100*theHost->ipv6Sent.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->nonIPTraffic != NULL) {
	if(theHost->nonIPTraffic->stpSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->stpSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
	}

	if(theHost->nonIPTraffic->ipxSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->ipxSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPX";
	}

	if(theHost->nonIPTraffic->dlcSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->dlcSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DLC";
	}

	if(theHost->nonIPTraffic->osiSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->osiSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "OSI";
	}

	if(theHost->nonIPTraffic->arp_rarpSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->arp_rarpSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
	}

	if(theHost->nonIPTraffic->decnetSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->decnetSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DECNET";
	}

	if(theHost->nonIPTraffic->appletalkSent.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->appletalkSent.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "AppleTalk";
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

      if(theHost->ipv6Rcvd.value > 0) {
	p[num] = (float)((100*theHost->ipv6Rcvd.value)/totTraffic.value);
	if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPv6";
      }

      if(theHost->nonIPTraffic != NULL) {
	if(theHost->nonIPTraffic->stpRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->stpRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "STP";
	}

	if(theHost->nonIPTraffic->ipxRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->ipxRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "IPX";
	}

	if(theHost->nonIPTraffic->dlcRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->dlcRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DLC";
	}

	if(theHost->nonIPTraffic->osiRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->osiRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "OSI";
	}

	if(theHost->nonIPTraffic->arp_rarpRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->arp_rarpRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "(R)ARP";
	}

	if(theHost->nonIPTraffic->decnetRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->decnetRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "DECNET";
	}

	if(theHost->nonIPTraffic->appletalkRcvd.value > 0) {
	  p[num] = (float)((100*theHost->nonIPTraffic->appletalkRcvd.value)/totTraffic.value);
	  if(p[num] > MIN_SLICE_PERCENTAGE) lbl[num++] = "AppleTalk";
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

    build_pie(num, p, lbl);
  }
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
    build_pie(num, p, lbl);
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

    if(dataSent)
      traf.value = theHost->trafficDistribution->last24HoursBytesSent[i].value;
    else
      traf.value = theHost->trafficDistribution->last24HoursBytesRcvd[i].value;

    if(traf.value > 0) {
      p[num] = traf.value;
      switch(i) {
      case 0:
	lbl[num++] = "12PM-1AM";
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
	lbl[num++] = "11-12AM";
	break;
      case 12:
	lbl[num++] = "12AM-1PM";
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
	lbl[num++] = "11-12PM";
	break;
      }
    }
  }

  if(num == 0) {
    traceEvent(CONST_TRACE_WARNING, "Graph failure (2)");
    return; /* TODO: this has to be handled better */
  }
  
  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie(num, p, lbl);
}

/* ************************ */

void hostTotalFragmentDistrib(HostTraffic *theHost, short dataSent) {
  float p[20];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int num=0;
  TrafficCounter totFragmentedTraffic, totTraffic;

  if(dataSent) {
    totTraffic.value = theHost->ipBytesSent.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsSent.value+theHost->udpFragmentsSent.value
      +theHost->icmpFragmentsSent.value;
  } else {
    totTraffic.value = theHost->ipBytesRcvd.value;
    totFragmentedTraffic.value = theHost->tcpFragmentsRcvd.value+theHost->udpFragmentsRcvd.value
      +theHost->icmpFragmentsRcvd.value;
  }

  if(totTraffic.value > 0) {
    p[num] = (float)((100*totFragmentedTraffic.value)/totTraffic.value);
    lbl[num++] = "Frag";

    p[num] = 100-((float)(100*totFragmentedTraffic.value)/totTraffic.value);
    if(p[num] > 0) { lbl[num++] = "Non Frag"; }

    if(num == 0) {
      traceEvent(CONST_TRACE_WARNING, "Graph failure (3)");
      return; /* TODO: this has to be handled better */
    }

    if(num == 1) p[0] = 100; /* just to be safe */
    build_pie(num, p, lbl);
  }
}

/* ************************ */

void hostIPTrafficDistrib(HostTraffic *theHost, short dataSent) {
  float p[MAX_NUM_PROTOS];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int i, num=0;
  TrafficCounter traffic, totalIPTraffic, diffTraffic;

  if(theHost->protoIPTrafficInfos == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Graph failure (5)");
    return;
  }

  totalIPTraffic.value = 0;
  diffTraffic.value = 0;

  if(dataSent)
    totalIPTraffic.value = theHost->ipBytesSent.value;
  else
    totalIPTraffic.value = theHost->ipBytesRcvd.value;

  if(totalIPTraffic.value > 0) {
    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      if(theHost->protoIPTrafficInfos[i]) {
	if(dataSent)
	  traffic.value = theHost->protoIPTrafficInfos[i]->sentLoc.value+theHost->protoIPTrafficInfos[i]->sentRem.value;
	else
	  traffic.value = theHost->protoIPTrafficInfos[i]->rcvdLoc.value+theHost->protoIPTrafficInfos[i]->rcvdFromRem.value;
      } else
	traffic.value = 0;
      
      if(traffic.value > 0) {
	p[num] = (float)((100*traffic.value)/totalIPTraffic.value);
	diffTraffic.value += traffic.value;
	lbl[num++] = myGlobals.ipTrafficProtosNames[i];
      }

      if(num >= MAX_NUM_PROTOS) break; /* Too much stuff */
    }
  }

  if(num == 0) {
    p[num] = 1;
    lbl[num++] = "Other";
  } else {
    if(diffTraffic.value < totalIPTraffic.value) {
      diffTraffic.value = totalIPTraffic.value - diffTraffic.value;
      p[num] = (float)((100*diffTraffic.value)/totalIPTraffic.value);
      lbl[num++] = "Other";
    }
  }

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie(num, p, lbl);
}

/* ********************************** */

void pktSizeDistribPie(void) {
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "", "" };
  int num=0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo64.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 64";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo128.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 128";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo256.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 256";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo512.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 512";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1024.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 1024";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 1518";
  };

#ifdef MAKE_WITH_JUMBO_FRAMES
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo2500.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 2500";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo6500.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 6500";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.upTo9000.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 9000";
  };
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above9000.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 9000";
  };
#else
  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdPktStats.above1518.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 1518";
  };
#endif


  if(num == 1) p[0] = 100; /* just to be safe */
  
  build_pie(num, p, lbl);
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
  build_pie(num, p, lbl);
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

  build_pie(num, p, lbl);
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
      p[myDevices]   = 100*(((float)p[i])/totPkts.value);
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

  build_pie(myDevices, p, lbl);
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

  build_pie(num, p, lbl);
}

/* ************************ */

void drawTrafficPie(void) {
  TrafficCounter ip;
  float p[2];
  char	*lbl[] = { "IP", "Non IP" };
  int num=0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value == 0) return;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  p[0] = ip.value*100/myGlobals.device[myGlobals.actualReportDeviceId].ethernetBytes.value; num++;
  p[1] = 100-p[0];

  if(p[1] > 0)
    num++;

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie(num, p, lbl);
}

/* ************************ */

void drawGlobalProtoDistribution(void) {
  TrafficCounter ip;
  float p[256]; /* Fix courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */
  char	*lbl[16];
  int idx = 0;

  ip.value = myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  if(myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].tcpBytes.value; lbl[idx] = "TCP";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].udpBytes.value; lbl[idx] = "UDP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].icmpBytes.value; lbl[idx] = "ICMP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherIpBytes.value; lbl[idx] = "Other IP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].arpRarpBytes.value; lbl[idx] = "(R)ARP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].dlcBytes.value; lbl[idx] = "DLC"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipxBytes.value; lbl[idx] = "IPX"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].decnetBytes.value;lbl[idx] = "Decnet";  idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].atalkBytes.value; lbl[idx] = "AppleTalk"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].netbiosBytes.value; lbl[idx] = "NetBios"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].osiBytes.value; lbl[idx] = "OSI"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipv6Bytes.value; lbl[idx] = "IPv6"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].stpBytes.value; lbl[idx] = "STP"; idx++; }
  if(myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value > 0) {
    p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].otherBytes.value; lbl[idx] = "Other"; idx++; }

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList) {
    ProtocolsList *protoList = myGlobals.ipProtosList;
    int idx1 = 0;

    while(protoList != NULL) {
      if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value > 0) {
	p[idx] = myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
	lbl[idx] = protoList->protocolName; idx++;
      }

      idx1++, protoList = protoList->next;
    }
  }


  {
    int i;
    float the_max = 0.1;

    for(i=0; i<idx; i++) the_max = max(the_max, p[i]);
    for(i=0; i<idx; i++) p[i]    = (p[i]*100)/the_max;
  }

  build_bar(idx, p, lbl);
}

/* ************************ */

void drawGlobalIpProtoDistribution(void) {
  int i, idx=0, idx1 = 0, maxNumDisplayProto = 13;
  float p[256];
  char *lbl[256];
  ProtocolsList *protoList = myGlobals.ipProtosList;
  float total, partialTotal = 0;

  total = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipBytes.value;

  if(myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList) {
    while(protoList != NULL) {
      if(total > (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value)
	total -= (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtosList[idx1].value;
      else
	total = 0;

      idx1++, protoList = protoList->next;
    }

    for(i=0; i<myGlobals.numIpProtosToMonitor; i++) {
      p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local.value
	+myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote.value;
      p[idx] += (float)myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].remote2local.value
	+myGlobals.device[myGlobals.actualReportDeviceId].ipProtoStats[i].local2remote.value;
      if((p[idx] > 0) && ((p[idx]*100/total) > 1 /* the proto is at least 1% */)) {
	partialTotal += p[idx];
	lbl[idx] = myGlobals.ipTrafficProtosNames[i];
	idx++;
      }

      if(idx >= maxNumDisplayProto) break;
    }
  }

  if(total == 0) total = 1;

  /*  Add a bar for the Other TCP/UDP based protocols
      Courtesy of Robbert Kouprie <r.kouprie@dto.tudelft.nl>
  */
  if (total > partialTotal) {
    lbl[idx] = "Other";
    p[idx] = total - partialTotal;
    idx++;
  }

  for(i=0; i<idx; i++) p[i] = (p[i] * 100)/total;

  build_pie(idx, p, lbl);
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

  build_pie(30, graphData, lbls);

  return(numPoints);
}

/* ************************ */

void hostFcTrafficDistrib(HostTraffic *theHost, short dataSent) {
  float p[MAX_NUM_PROTOS];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "",
		   "", "", "", "", "", "", "", "", "", "" };
  int i, num=0, explodePieces[MAX_NUM_PROTOS];
  TrafficCounter traffic, totalFcTraffic, diffTraffic;
  char *lblstouse[] = { "SCSI", "FICON", "ELS", "NS", "IP/FC", "Others"};
  Counter protoTrafficSent[] = {
      theHost->fcCounters->fcFcpBytesSent.value,
      theHost->fcCounters->fcFiconBytesSent.value,
      theHost->fcCounters->fcElsBytesSent.value,
      theHost->fcCounters->fcDnsBytesSent.value,
      theHost->fcCounters->fcIpfcBytesSent.value,
      theHost->fcCounters->otherFcBytesSent.value,
  };

  Counter protoTrafficRcvd[] = {
      theHost->fcCounters->fcFcpBytesRcvd.value,
      theHost->fcCounters->fcFiconBytesRcvd.value,
      theHost->fcCounters->fcElsBytesRcvd.value,
      theHost->fcCounters->fcDnsBytesRcvd.value,
      theHost->fcCounters->fcIpfcBytesRcvd.value,
      theHost->fcCounters->otherFcBytesRcvd.value,
  };

  totalFcTraffic.value = 0;
  diffTraffic.value = 0;

  if(dataSent)
      totalFcTraffic.value = theHost->fcCounters->fcBytesSent.value;
  else
      totalFcTraffic.value = theHost->fcCounters->fcBytesRcvd.value;
  
  if(totalFcTraffic.value > 0) {
      for (i = 0; i < 6; i++) {
          if(dataSent) 
              traffic.value = protoTrafficSent[i];
          else 
              traffic.value = protoTrafficRcvd[i];

          if(traffic.value > 0) {
              p[num] = (float)((100*traffic.value)/totalFcTraffic.value);
              diffTraffic.value += traffic.value;

              if(num == 0)
                  explodePieces[num]=10;
              else
                  explodePieces[num]=explodePieces[num-1];
              if (p[num]<5.0)
                  explodePieces[num]+=9;
              else if (p[num]>10.0)
                  explodePieces[num]=10;
              
              lbl[num++] = lblstouse[i];
          }
      }
  }

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie(num, p, lbl);
}

/* ********************************** */

void fcPktSizeDistribPie(void) {
  float p[10];
  char	*lbl[] = { "", "", "", "", "", "", "", "", "", ""};
  int num=0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo36.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo36.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 36";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo48.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo48.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 48";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo52.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo52.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 52";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo68.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo68.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 68";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo104.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo104.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 104";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo548.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo548.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 548";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo1060.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo1060.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 1060";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo2136.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.upTo2136.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "<= 2136";
  };

  if(myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value > 0) {
    p[num] = (float)(100*myGlobals.device[myGlobals.actualReportDeviceId].rcvdFcPktStats.above2136.value)/
      (float)myGlobals.device[myGlobals.actualReportDeviceId].ethernetPkts.value;
    lbl[num++] = "> 2136";
  };

  if(num == 1) p[0] = 100; /* just to be safe */
  build_pie(num, p, lbl);
}

/* ******************************** */

void drawGlobalFcProtoDistribution(void) {
  int idx=0;
  float p[256];
  char *lbl[256];

  p[myGlobals.numIpProtosToMonitor] = 0;

  if(myGlobals.device[myGlobals.actualReportDeviceId].fcFcpBytes.value) {
      p[idx]  = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcFcpBytes.value;
      lbl[idx++] = "SCSI";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcFiconBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcFiconBytes.value;
      lbl[idx++] = "FICON";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcElsBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcElsBytes.value;
      lbl[idx++] = "ELS";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcIpfcBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcIpfcBytes.value;
      lbl[idx++] = "IP/FC";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcDnsBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcDnsBytes.value;
      lbl[idx++] = "NS";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].fcSwilsBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].fcSwilsBytes.value;
      lbl[idx++] = "SWILS";
  }

  if (myGlobals.device[myGlobals.actualReportDeviceId].otherFcBytes.value) {
      p[idx] = (float)myGlobals.device[myGlobals.actualReportDeviceId].otherFcBytes.value;
      lbl[idx++] = "Others";
  }

  build_bar(idx, p, lbl);
}

/* *******************************************************/

void drawLunStatsBytesDistribution(HostTraffic *el) {
  int lun, numEntries, idx=0;
  float p[MAX_LUNS_GRAPHED+1];
  char *lbl[MAX_LUNS_GRAPHED+1];
  char label[MAX_LUNS_GRAPHED+1][10];
  LunStatsSortedEntry sortedLunTbl[MAX_LUNS_SUPPORTED];
  LunStatsSortedEntry *entry;
  ScsiLunTrafficInfo *lunStats;

  p[MAX_LUNS_GRAPHED] = 0;
  numEntries = 0;

  memset(sortedLunTbl, 0, sizeof (sortedLunTbl));

  for (lun=0, numEntries=0; lun < MAX_LUNS_SUPPORTED; lun++) {
    if ((lunStats = el->fcCounters->activeLuns[lun]) != NULL) {
          sortedLunTbl[numEntries].lun = lun;
          sortedLunTbl[numEntries++].stats = el->fcCounters->activeLuns[lun];
      }
  }

  myGlobals.columnSort = 4;     /* This is based on total I/O */
  qsort (sortedLunTbl, numEntries, sizeof (LunStatsSortedEntry), cmpLunFctn);

  idx = 0;
  for (lun = numEntries-1; ((idx < MAX_LUNS_GRAPHED) && (lun >= 0));
       lun--) {
      entry = &sortedLunTbl[lun];
      p[idx] = (float) (entry->stats->bytesSent.value +
                        entry->stats->bytesRcvd.value);
      if (p[idx] > 0) {
          safe_snprintf(__FILE__, __LINE__, label[idx], sizeof(label[idx]), "%hd", entry->lun);
          lbl[idx] = label[idx];
          idx++;
      }
  }
  
  build_bar(idx, p, lbl);
}

/* *******************************************************/

void drawLunStatsPktsDistribution(HostTraffic *el) {
  int lun, numEntries, idx=0;
  float p[MAX_LUNS_GRAPHED+1];
  char *lbl[MAX_LUNS_GRAPHED+1];
  char label[MAX_LUNS_GRAPHED+1][10];
  ScsiLunTrafficInfo *lunStats;
  LunStatsSortedEntry sortedLunTbl[MAX_LUNS_SUPPORTED];
  LunStatsSortedEntry *entry;

  p[MAX_LUNS_GRAPHED] = 0;
  numEntries = 0;

  memset(sortedLunTbl, 0, sizeof (sortedLunTbl));

  for (lun=0, numEntries=0; lun < MAX_LUNS_SUPPORTED; lun++) {
      if ((lunStats = el->fcCounters->activeLuns[lun]) != NULL) {
          sortedLunTbl[numEntries].lun = lun;
          sortedLunTbl[numEntries++].stats = el->fcCounters->activeLuns[lun];
      }
  }

  myGlobals.columnSort = 5;     /* This is based on total frames */
  qsort (sortedLunTbl, numEntries, sizeof (LunStatsSortedEntry), cmpLunFctn);
  
  for (lun = numEntries-1; ((idx < MAX_LUNS_GRAPHED) && (lun >= 0));
       lun--) {
      entry = &sortedLunTbl[lun];
      p[idx] = (float) (entry->stats->pktRcvd +
                        entry->stats->pktSent);
      if (p[idx] > 0) {
          sprintf (label[idx],"%hd", entry->lun);
          lbl[idx] = label[idx];
          idx++;
      }
  }

  build_bar(idx, p, lbl);
}

/* *******************************************************/

void drawVsanStatsBytesDistribution(int deviceId) {
  int numVsans, idx=0, i, j;
  float p[MAX_VSANS_GRAPHED+1];
  char *lbl[MAX_VSANS_GRAPHED+1];
  char label[MAX_VSANS_GRAPHED+1][10];
  FcFabricElementHash **theHash;
  FcFabricElementHash *tmpTable[MAX_ELEMENT_HASH];
  
  if ((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
      return;
  }

  p[MAX_VSANS_GRAPHED] = 0;
  numVsans = 0;

  memset (tmpTable, 0, sizeof (FcFabricElementHash *)*MAX_ELEMENT_HASH);
  for (i=0; i<MAX_ELEMENT_HASH; i++) {
      if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
         (theHash[i]->vsanId < MAX_USER_VSAN)) {
          if (theHash[i]->totBytes.value)
              tmpTable[numVsans++] = theHash[i];
      }
  }

  if (!numVsans) {
      printNoDataYet ();
      return;
  }
  
  myGlobals.columnSort = 3;
  qsort (tmpTable, numVsans, sizeof (FcFabricElementHash **), cmpVsanFctn);
  
  idx = 0;
  for (i = numVsans-1, j = 0; i >= 0; i--, j++) {
      if (tmpTable[i] != NULL) {
          p[idx] = tmpTable[i]->totBytes.value;
          if (tmpTable[i]->vsanId) {
              sprintf (label[idx], "%hd", tmpTable[i]->vsanId);
          }
          else {
              sprintf (label[idx], "N/A");
          }
          lbl[idx] = label[idx];
	  idx++;
      }

      if (j >= MAX_VSANS_GRAPHED)
          break;
  }

  build_bar(idx, p, lbl);  
}

/* *******************************************************/

void drawVsanStatsPktsDistribution(int deviceId) {
  int numVsans, idx=0, i, j;
  float p[MAX_VSANS_GRAPHED+1];
  char *lbl[MAX_VSANS_GRAPHED+1];
  char label[MAX_VSANS_GRAPHED+1][10];
  FcFabricElementHash **theHash;
  FcFabricElementHash *tmpTable[MAX_ELEMENT_HASH];
  
  if ((theHash = myGlobals.device[deviceId].vsanHash) == NULL) {
      return;
  }

  p[MAX_VSANS_GRAPHED] = 0;
  numVsans = 0;

  memset (tmpTable, 0, sizeof (FcFabricElementHash *)*MAX_ELEMENT_HASH);
  for (i=0; i<MAX_ELEMENT_HASH; i++) {
      if((theHash[i] != NULL) && (theHash[i]->vsanId < MAX_HASHDUMP_ENTRY) &&
         (theHash[i]->vsanId < MAX_USER_VSAN)) {
          if (theHash[i]->totPkts.value)
              tmpTable[numVsans++] = theHash[i];
      }
  }

  if (!numVsans) {
      printNoDataYet ();
      return;
  }
  
  myGlobals.columnSort = 4;
  qsort (tmpTable, numVsans, sizeof (FcFabricElementHash **), cmpVsanFctn);
  
  idx = 0;
  for (i = numVsans-1, j = 0; i >= 0; i--, j++) {
      if (tmpTable[i] != NULL) {
          p[idx] = tmpTable[i]->totPkts.value;
          if (tmpTable[i]->vsanId) {
              sprintf (label[idx], "%d", tmpTable[i]->vsanId);
          }
          else {
              sprintf (label[idx], "N/A");
          }
	  
          lbl[idx] = label[idx];
	  idx++;
      }

      if (j >= MAX_VSANS_GRAPHED)
          break;
  }

  build_bar(idx, p, lbl);
}

/* *******************************************************/

void drawVsanSwilsProtoDistribution(u_short vsanId) {
  int idx=0;
  FcFabricElementHash *hash;
  float p[256];
  char *lbl[256];

  p[myGlobals.numIpProtosToMonitor] = 0;

  hash = getFcFabricElementHash (vsanId, myGlobals.actualReportDeviceId);
  
  p[0] = (float)hash->dmBytes.value;
  if (p[0] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[0];
      lbl[idx++] = "DM";
  }

  p[1] = (float)hash->fspfBytes.value;
  if (p[1] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[1];
      lbl[idx++] = "FSPF";
  }

  p[2] = (float)hash->nsBytes.value;
  if (p[2] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[2];
      lbl[idx++] = "NS";
  }

  p[3] = (float)hash->zsBytes.value;
  if (p[3] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[3];
      lbl[idx++] = "ZS";
  }

  p[4] = (float)hash->rscnBytes.value;
  if (p[4] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[4];
      lbl[idx++] = "SW_RSCN";
  }

  p[5] = (float)hash->fcsBytes.value;
  if (p[5] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[5];
      lbl[idx++] = "FCS";
  }

  p[6] = (float)hash->otherCtlBytes.value;
  if (p[6] > 0) {
      p[myGlobals.numIpProtosToMonitor] += p[6];
      lbl[idx++] = "Others";
  }

  build_pie(idx, p, lbl);
}

/* *******************************************************/

void drawVsanDomainTrafficDistribution(u_short vsanId, u_char dataSent) {
  int i, idx=0, numEntries = 0;
  FcFabricElementHash *hash;
  float p[MAX_VSANS_GRAPHED+1];
  char *lbl[MAX_VSANS_GRAPHED+1], labels[MAX_VSANS_GRAPHED+1][8];
  Counter total;
  SortedFcDomainStatsEntry *fcDomainStats;

  p[MAX_FC_DOMAINS+1] = 0;

  hash = getFcFabricElementHash (vsanId, myGlobals.actualReportDeviceId);

  if (hash == NULL) {
      printNoDataYet();
      return;
  }

  fcDomainStats = (SortedFcDomainStatsEntry *)malloc (MAX_FC_DOMAINS*sizeof (SortedFcDomainStatsEntry));
  if (fcDomainStats == NULL) {
      traceEvent (CONST_TRACE_WARNING, "Unable to allocate memory for SortedFcDomainStatsEntry\n");
      printNoDataYet();
      return;
  }
  memset (fcDomainStats, 0, MAX_FC_DOMAINS*sizeof (SortedFcDomainStatsEntry));
  
  for (i = 1; i < MAX_FC_DOMAINS; i++) {
      if (dataSent) {
          if (hash->domainStats[i].sentBytes.value) {
              fcDomainStats[numEntries].domainId = i;
              fcDomainStats[numEntries++].stats = &hash->domainStats[i];
          }
      }
      else {
          if (hash->domainStats[i].rcvdBytes.value) {
              fcDomainStats[numEntries].domainId = i;
              fcDomainStats[numEntries++].stats = &hash->domainStats[i];
          }
      }
  }

  if (numEntries == 0) {
      printNoDataYet();
      return;
  }

  myGlobals.columnSort = dataSent;
  qsort(fcDomainStats, numEntries, sizeof (SortedFcDomainStatsEntry), cmpFcDomainFctn);
  
  for (i = numEntries-1; (idx < MAX_VSANS_GRAPHED) && (i >= 0); i--) {
      if (dataSent) {
          total = fcDomainStats[i].stats->sentBytes.value;
      }
      else {
          total = fcDomainStats[i].stats->rcvdBytes.value;
      }
      if (total > 0) {
          p[idx] = (float)total;
          sprintf (labels[idx], "%x", fcDomainStats[i].domainId);
          lbl[idx] = labels[idx];
          idx++;
      }
  }

  build_pie(idx, p, lbl);
}
