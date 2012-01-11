/*
 *  Copyright (C) 2008-10 Luca Deri <deri@ntop.org>
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
#include "globals-report.h"

#define MAX_NUM_MAP_HOSTS 5120


const char *map_head = "<script type=\"text/javascript\" src=\"http://maps.googleapis.com/maps/api/js?sensor=false";
const char *map_head2 = "\"></script>\n    <script type=\"text/javascript\"><!--\n\n    function load_map() { \n";
const char *map_head3 = " addReflections();\n";
const char *map_head4 = " \n function createMarker(point,html) { \n var infowindow = new google.maps.InfoWindow({ \n content: html \n }); \n var marker = new google.maps.Marker({ \n position: point \n }); \n google.maps.event.addListener(marker, \"click\", function() { \n infowindow.open(map,marker); \n }); \n marker.setMap(map); \n } \n \n var myOptions = { \n zoom: 2, \n center: new google.maps.LatLng(43.72, 10.40), \n panControl: true, \n zoomControl: true, \n scaleControl: true, \n mapTypeId: google.maps.MapTypeId.ROADMAP \n };\n \n var map = new google.maps.Map(document.getElementById(\"map\"),myOptions); \n";

const char *map_tail = "\n      }\n\n        --></script>\n  </head>\n  <body onload=\"load_map()\">\n    <center><div id=\"map\" style=\"width: 800px; height: 600px\"></div></center>\n\n";

const char *map_tail2 = "\n      }\n\n        --></script>\n <div id=\"map\" style=\"width: 800px; height: 600px\"></div>\n<script type=\"text/javascript\">\nload_map();\n</script>\n";

/* ******************************************** */

static char *googleMapsKey = NULL;

void init_maps() {
  char value[128];

  if(fetchPrefsValue("google_maps.key", value, sizeof(value)) == -1) {
    storePrefsValue("google_maps.key", GOOGLE_DEFAULT_MAP_KEY);
    googleMapsKey = GOOGLE_DEFAULT_MAP_KEY;
  } else {
    googleMapsKey = strdup(value);
  }
}

/* ************************************************** */

static char* escape_string(char *in, char *out, u_int out_len) {
  int i, i_max=strlen(in), j;

  for(i=0, j=0; i<i_max; i++) {
    switch(in[i]) {
    case '\'':
    case '\"':
      out[j++] = '\\'; 
      if(j >= out_len-1) return(out);
      /* No break here */
    default:
      out[j++] = in[i];
      if(j >= out_len-1) return(out);
      break;
    }
  }

  return(out);
}

/* ************************************************** */

void createAllHostsMap(void) {
  HostTraffic *el;
  int num_hosts = 0;

  sendString((char*)map_head);
  //sendString(googleMapsKey);
  sendString((char*)map_head2);
  sendString((char*)map_head3);
  sendString((char*)map_head4);
  
  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {
    if(el->geo_ip) {
      char buf[512], buf1[256] = { 0 };
      int showSymIp;

      if((el->hostResolvedName[0] != '\0')
	 && strcmp(el->hostResolvedName, el->hostNumIpAddress)
	 && (!subnetPseudoLocalHost(el)))
	showSymIp = 1;
      else
	showSymIp = 0;

      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
 		    "createMarker(new google.maps.LatLng(%.2f, %.2f), \""
#if 0
		    "%s%s"
#endif
		    "<A HREF=/%s.html>%s</A><br>%s<br>%s\");\n", 
		    el->geo_ip->latitude, el->geo_ip->longitude,
#if 0
		    showSymIp ? escape_string(el->hostResolvedName, buf1, sizeof(buf1)) : "", showSymIp ? "<br>" : "",
#endif
		    el->hostNumIpAddress, el->hostNumIpAddress,
		    el->geo_ip->city ? el->geo_ip->city : "", 
		    el->geo_ip->country_name ? el->geo_ip->country_name : "");
      sendString(buf);
      num_hosts++;
      if(num_hosts > MAX_NUM_MAP_HOSTS) break; /* Too many hosts */
    }
  }

  sendString((char*)map_tail);

  if(num_hosts > MAX_NUM_MAP_HOSTS)
    sendString("<p><center><b><font color=red>WARNING:</font></b>You have more hosts to display than the number typically supported by Google maps. Some hosts have not been rendered.</center></p>");

//  sendString("<p><center><b><font color=red>NOTE:</font></b> ");
//  sendString("make sure you get your key <a href=http://code.google.com/apis/maps/>here</A>"
//	  " for using Google Maps from ntop and register it as \'google_maps.key\' key <A href=/"CONST_EDIT_PREFS"#google_maps.key>here</A>.</center></p>\n"); 
}

/* ************************************************** */

void createHostMap(HostTraffic *host) {
  HostTraffic *el;
  int num_hosts = 0;

  sendString((char*)map_head);
  //sendString(googleMapsKey);
  sendString((char*)map_head2);
  sendString((char*)map_head4);
  
  for(el=getFirstHost(myGlobals.actualReportDeviceId);
      el != NULL; el = getNextHost(myGlobals.actualReportDeviceId, el)) {

    if((el->l2Host == host->l2Host) && (el->hostIpAddress.hostFamily == host->hostIpAddress.hostFamily)) {
      if((CM_PointEst(host->sent_to_matrix, el->serialHostIndex) > 0)
	 || (CM_PointEst(host->recv_from_matrix, el->serialHostIndex) > 0)) {
	if(el->geo_ip) {
	  char buf[512], buf1[256] = { 0 };
	  int showSymIp;

	  if((el->hostResolvedName[0] != '\0')
	     && strcmp(el->hostResolvedName, el->hostNumIpAddress)
	     && (!privateIPAddress(el)))
	    showSymIp = 1;
	  else
	    showSymIp = 0;

	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			"createMarker(new google.maps.LatLng(%.2f, %.2f), \""
#if 0
			"%s%s"
#endif
			"<A HREF=/%s.html>%s</A><br>%s<br>%s\");\n", 
			el->geo_ip->latitude, el->geo_ip->longitude,
#if 0
			showSymIp ? escape_string(el->hostResolvedName, buf1, sizeof(buf1)) : "", 
			showSymIp ? "<br>" : "",
#endif
			el->hostNumIpAddress, el->hostNumIpAddress,
			el->geo_ip->city ? el->geo_ip->city : "", 
			el->geo_ip->country_name ? el->geo_ip->country_name : "");
	  sendString(buf);
	  num_hosts++;
	  if(num_hosts > MAX_NUM_MAP_HOSTS) break; /* Too many hosts */
	}
      }
    }
  }

  sendString((char*)map_tail2);
}

