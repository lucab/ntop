/*
 *  Copyright (C) 2002 Luca Deri <deri@ntop.org>
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

static short initialized = 0;

/* ****************************** */

static void initNetFlowFunct(void) {
  int i;
  char key[32], value[32];

  for(i=0; i<myGlobals.numDevices; i++)
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(key, sizeof(key),
		  "%s.exportNetFlow",
		  myGlobals.device[i].name) < 0)
	traceEvent(TRACE_ERROR, "Buffer overflow!");

      if(fetchPrefsValue(key, value, sizeof(value)) == -1) {
	storePrefsValue(key, "No");
      } else {	
	/* traceEvent(TRACE_INFO, "%s=%s", key, value); */

	if(strcmp(value, "Yes") == 0)
	  myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_ENABLED;
	else
	  myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_DISABLED;
      }
    }
}

/* ****************************** */

static void handleNetflowHTTPrequest(char* url) {
  char buf[512];
  int i;

  sendHTTPHeader(HTTP_TYPE_HTML, 0);
  printHTMLheader("NetFlow Statistics", 0);

  sendString("<CENTER>\n<HR>\n");

  if(url != NULL) {
    char *device, *value;

    device = strtok(url, "=");
    if(device != NULL) value = strtok(NULL, "=");

    if(value && device) {
      for(i=0; i<myGlobals.numDevices; i++)
	if(!myGlobals.device[i].virtualDevice) {
	  if(strcmp(myGlobals.device[i].name, device) == 0) {
	    if(snprintf(buf, sizeof(buf),
			"%s.exportNetFlow",
			myGlobals.device[i].name) < 0)
	      traceEvent(TRACE_ERROR, "Buffer overflow!");

	    /* traceEvent(TRACE_INFO, "%s=%s", buf, value); */
	    storePrefsValue(buf, value);

	    if(!strcmp(value, "No")) {
	      myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_DISABLED;
	    } else {
	      myGlobals.device[i].exportNetFlow = NETFLOW_EXPORT_ENABLED;
	    }
	  }
	}
    }
  }

  sendString("<TABLE BORDER>\n");
  sendString("<TR><TH>Interface Name</TH><TH>NetFlow Enabled</TH></TR>\n");

  for(i=0; i<myGlobals.numDevices; i++) {
    if(!myGlobals.device[i].virtualDevice) {
      if(snprintf(buf, sizeof(buf), "<TR><TH ALIGN=LEFT>%s</TH><TD ALIGN=RIGHT>"
		  "<A HREF=/plugins/netflowPrefs?%s=%s>%s</A></TD></TR>\n",
		  myGlobals.device[i].name, myGlobals.device[i].name,
		  myGlobals.device[i].exportNetFlow == NETFLOW_EXPORT_ENABLED ? "No" : "Yes",
		  myGlobals.device[i].exportNetFlow == NETFLOW_EXPORT_ENABLED ? "Yes" : "No"
		  ) < 0)
	BufferOverflow();
      sendString(buf);
    }
  }

  sendString("</TABLE>\n<P>\n");

  if(!myGlobals.enableNetFlowSupport)
    sendString("<FONT COLOR=red>NOTE: NetFlow support is currently disabled. "
	       "Please use the -g flag to enable it.</FONT>\n");

  sendString("<p></CENTER>\n");

  printHTMLtrailer();
}

/* ****************************** */

static void termNetflowFunct(void) {
  traceEvent(TRACE_INFO, "Thanks for using ntop NetFlow");
  traceEvent(TRACE_INFO, "Done.\n");
  fflush(stdout);
}

/* ****************************** */

static PluginInfo netflowPluginInfo[] = {
  { "netflowPrefs",
    "This plugin is used to modify NetFlow preferences",
    "1.0", /* version */
    "<A HREF=http://luca.ntop.org/>L.Deri</A>",
    "netflowPrefs", /* http://<host>:<port>/plugins/netflowPrefs */
    1, /* Active */
    initNetFlowFunct, /* InitFunc   */
    NULL, /* TermFunc   */
    NULL, /* PluginFunc */
    handleNetflowHTTPrequest,
    NULL /* no capture */
  }
};

/* ***************************************** */

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* netflowPluginEntryFctn(void) {
#else
  PluginInfo* PluginEntryFctn(void) {
#endif
    traceEvent(TRACE_INFO, "Welcome to %s. (C) 2002 by Luca Deri.\n",
	       netflowPluginInfo->pluginName);
    
    return(netflowPluginInfo);
  }
