/*
 *  Copyright (C) 2008-09 Luca Deri <deri@ntop.org>
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

#define MAX_NUM_MAP_HOSTS 512

const char *map_head = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\n  <head>\n    <meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"/>\n    <script src=\"http://maps.google.com/maps?file=api&amp;v=2&amp;key=";
const char *map_head2 = "\"\n      type=\"text/javascript\"></script>\n    <script type=\"text/javascript\">\n\n    //<![CDATA[\n\n    function load() {\n      if (GBrowserIsCompatible()) {\n\n       function createMarker(point,html) {\n        var marker = new GMarker(point);\n        GEvent.addListener(marker, \"click\", function() {\n          marker.openInfoWindowHtml(html);\n        });\n        return marker;\n      }\n\n        var map = new GMap2(document.getElementById(\"map\"));\n\n        map.addControl(new GLargeMapControl()); map.addControl(new GMapTypeControl());\n        map.addControl(new GMapTypeControl(true));\n        map.setCenter(new GLatLng(43.72, 10.40), 2);\n";

const char *map_tail = "\n      }\n    }\n\n    //]]>\n    </script>\n  </head>\n  <body onload=\"load()\" onunload=\"GUnload()\">\n    <center><div id=\"map\" style=\"width: 800px; height: 600px\"></div></center>\n\n  </body>\n</html>\n";

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

char* escape_string(char *in, char *out, u_int out_len) {
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

void create_host_map() {
  HostTraffic *el;
  int num_hosts = 0;

  sendString((char*)map_head);
  sendString(googleMapsKey);
  sendString((char*)map_head2);
  
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
		    "map.addOverlay(createMarker(new GLatLng(%.2f, %.2f), '%s%s<A HREF=/%s.html>%s</A><br>%s<br>%s'));\n",
		    el->geo_ip->latitude, el->geo_ip->longitude,
		    showSymIp ? escape_string(el->hostResolvedName, buf1, sizeof(buf1)) : "", 
		    showSymIp ? "<br>" : "",
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

  sendString("<p><center><b><font color=red>NOTE:</font></b> ");
  sendString("make sure you get your key <a href=http://code.google.com/apis/maps/>here</A>"
	  " for using Google Maps from ntop and register it as \'google_maps.key\' key <A href=/"CONST_EDIT_PREFS"#google_maps.key>here</A>.</center></p>\n"); 
}

