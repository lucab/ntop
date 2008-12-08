/*
 * 
 *  Copyright (C) 2006-07 Luca Deri <deri@ntop.org>
 *                      
 *                 http://www.ntop.org/
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

/* Forward */
static int initRemoteFunct(void);
static void termRemoteFunct(u_char termNtop);
static void handleRemoteHTTPrequest(char* url);

/* Static */
static int sock = -1;
static pthread_t remoteThread;

/* ****************************** */

static PluginInfo RemotepluginInfo[] = {
  {
    VERSION, /* current ntop version */
    "Remote",
    "This plugin allows remote applications to access ntop data",
    "0.1",            /* version */
    "<a class=mailto href=\"mailto:deri@ntop.org\">L. Deri</A>", 
    "Remoteplugin",      /* http://<host>:<port>/plugins/Remoteplugin */
    0,                /* Active by default */
    ViewOnly,
    0,                /* Inactive setup */
    initRemoteFunct,  /* InitFunc */
    termRemoteFunct,  /* TermFunc */
    NULL,             /* PluginFunc */
    handleRemoteHTTPrequest, /* http request handler */
    NULL,             /* no host creation/deletion handle */
    NULL,             /* BPF Filter */
    NULL,             /* no status */
    NULL              /* no extra pages */
  }
};

/* ****************************** */
/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo* remotePluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, 
	     "Remote: Welcome to %s. (C) 2006-07 by L.Deri",  
	     RemotepluginInfo->pluginName);
  
  return(RemotepluginInfo);
}

/* ****************************** */

static void* remoteMainLoop(void* notUsed _UNUSED_) {
  while(myGlobals.ntopRunState < FLAG_NTOPSTATE_SHUTDOWN) {
    fd_set remoteMask;
    int rc, all_right = 1;
    char buf[1500] = { '\0' }, rsp[1500] = { '\0' };

    FD_ZERO(&remoteMask);
    FD_SET(sock, &remoteMask);
    
    if((rc = select(sock+1, &remoteMask, NULL, NULL, NULL)) > 0) {
      char *method = NULL, *reference = NULL, *strtokstate;
      void *ref = NULL;
      struct sockaddr_in from;
      socklen_t fromlen = sizeof(from);

      memset(buf, 0, sizeof(buf));
      rc = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen); 
      traceEvent(CONST_TRACE_INFO, "Received %d bytes [%s]", rc, buf);

      method = strtok_r(buf, "\n;", &strtokstate);
      if(method) {
	if((reference = strtok_r(NULL, "\n;", &strtokstate))) {
	  traceEvent(CONST_TRACE_INFO, "-> '%s'", reference);

	  if(!strncmp(reference, "reference: 0x", 13)) {
	    reference += 13; /* Move to the reference pointer */

	    sscanf(reference, "%p", &ref);
	    traceEvent(CONST_TRACE_INFO, "---> '%p'", ref);
	  }
	}
      }    

      if(method && reference && all_right) {
	if(!strncmp(method, "call: ", 6)) {
	  int device;

	  method += 6; /* Move to the method name */

	  traceEvent(CONST_TRACE_INFO, "Method '%s'", method);

	  if(!strncmp(method, "getFirstHost", strlen("getFirstHost"))) {   
	    /* getFirstHost(device) */
	    method += 1+strlen("getFirstHost");
	    device = atoi(method);

	    if(device >= myGlobals.numDevices)
	      safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: parameter out of range;\n");
	    else {
	      HostTraffic *el = getFirstHost(device);
	      add_valid_ptr(el);
	      safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "rsp: ok;\nreference: %p;\n", el);
	    }
	  } else if(!strncmp(method, "getNextHost", strlen("getNextHost"))) {
	    /* getNextHost(device) */
            method += 1+strlen("getNextHost");
	    device = atoi(method);
	    
	    if(device >= myGlobals.numDevices)
	      safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: parameter out of range;\n");
	    else if((ref == NULL) || (!is_valid_ptr((void*)ref)))
	      safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: invalid reference;\n");
	    else {
	      HostTraffic *el = (HostTraffic*)ref, *next;
	      remove_valid_ptr(el);
	      next = getNextHost(device, el);
	      add_valid_ptr(next);
              safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "rsp: ok;\nreference: %p;\n", next);
	    }	      
	  } else if(!strncmp(method, "getHostAttribute", strlen("getHostAttribute"))) {
	    /* getHostAttribute(<attribute name>) */

	    if((ref == NULL) || (!is_valid_ptr((void*)ref)))
	      safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: invalid reference;\n");
	    else {
	      HostTraffic *el = (HostTraffic*)ref;
	      char *attr = method+1+strlen("getHostAttribute");
	      char *ret = NULL;
	      
	      attr[strlen(attr)-1] = '\0';

	      if(!strcmp(attr, "ethAddress"))            ret = el->ethAddressString;
	      else if(!strcmp(attr, "hostNumIpAddress")) ret = el->hostNumIpAddress;
	      
	      if(ret != NULL)
		safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "rsp: ok;\nreference: %p;\nvalue: %s;\n", el, ret);
	      else
		safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: unknown host attribute;\n");
	    }
	  } else
	    safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: unknown method;\n");
	}
      } else
	safe_snprintf(__FILE__, __LINE__, rsp, sizeof(rsp), "error: invalid parameters format;\n");

      rc = sendto(sock, rsp, strlen(rsp), 0, (struct sockaddr*)&from, fromlen);
      traceEvent(CONST_TRACE_INFO, "Sent %d bytes [%s]", rc, rsp);
    }
  }

  traceEvent(CONST_TRACE_INFO, "Remote plugin TERMLOOP");

  return(NULL);
}

/* ****************************** */

  static int initRemoteFunct(void) {
  int sockopt = 1, rc;
  struct sockaddr_in sockIn;

  traceEvent(CONST_TRACE_INFO, "Welcome to the Remote plugin");

  if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    traceEvent(CONST_TRACE_ERROR, "REMOTE: unable to create UDP socket");
    return -1;
  }
  rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));
  
  memset(&sockIn, 0, sizeof(sockIn));
  sockIn.sin_family = AF_INET;
  sockIn.sin_port   = (int)htons(myGlobals.runningPref.webPort);
  sockIn.sin_addr.s_addr = INADDR_ANY;
  errno = 0;

  rc = bind(sock, (struct sockaddr *)&sockIn, sizeof(sockIn));

  if((rc < 0) || (errno != 0)) {
    closeNwSocket(&myGlobals.sock);
    traceEvent(CONST_TRACE_ERROR, "REMOTE: binding problem '%s'(%d), plugin disabled", strerror(errno), errno);
    closeNwSocket(&sock);
    sock = -1;
    return(-1);
  } else {
    traceEvent(CONST_TRACE_INFO, "Remote plugin listening on UDP port %d",
	       myGlobals.runningPref.webPort);
    createThread(&remoteThread, remoteMainLoop, NULL);
  }

  return(0);
}

/* ****************************** */

static void termRemoteFunct(u_char termNtop /* 0=term plugin, 1=term ntop */) {
  if(remoteThread)  killThread(&remoteThread);
  if(sock != -1)    closeNwSocket(&sock);

  traceEvent(CONST_TRACE_INFO, "Remote: Thanks for using ntop Remote plugin");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Remote: Done");
}

/* ****************************** */

static void handleRemoteHTTPrequest(char* url /* NOTUSED */) {
  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("Remote Plugin", NULL, 0);
  sendString("<center>This plugin is not supposed to display you anything as it<br>"
	     "implements remote network access to ntop</center>\n");
  printHTMLtrailer();
}
