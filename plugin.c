/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *  			  Centro SERRA, University of Pisa
 *  			  http://www.ntop.org/
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

#ifdef STATIC_PLUGIN
extern PluginInfo* icmpPluginEntryFctn();
extern PluginInfo* arpPluginEntryFctn();
extern PluginInfo* nfsPluginEntryFctn();
extern PluginInfo* wapPluginEntryFctn();
extern PluginInfo* remIntPluginEntryFctn();
extern PluginInfo* rmonPluginEntryFctn();
#endif

#ifndef RTLD_NOW 
#define RTLD_NOW RTLD_LAZY 
#endif

/* ******************* */

void notifyPluginsHashResize(u_int oldSize, u_int newSize, u_int* mappings) {
  FlowFilterList *flows = flowsList;

  while(flows != NULL)
    if((flows->pluginStatus.pluginPtr != NULL)
       && (flows->pluginStatus.activePlugin)
       && (flows->pluginStatus.pluginPtr->resizeFunct != NULL)) {
      void (*resizeFunc)(u_int, u_int, u_int*);
 
      resizeFunc = (void(*)(u_int, u_int, u_int*))flows->pluginStatus.pluginPtr->resizeFunct;

      resizeFunc(oldSize, newSize, mappings);
    } else
      flows = flows->next;
}

/* ******************* */

int handlePluginHTTPRequest(char* url) {
  FlowFilterList *flows = flowsList;

  while(flows != NULL)
    if((flows->pluginStatus.pluginPtr != NULL)
       && (flows->pluginStatus.pluginPtr->pluginURLname != NULL)
       && (flows->pluginStatus.activePlugin)
       && (flows->pluginStatus.pluginPtr->httpFunct != NULL)
       && (strncmp(flows->pluginStatus.pluginPtr->pluginURLname,
		   url, strlen(flows->pluginStatus.pluginPtr->pluginURLname)) == 0)) {
      void (*httpFunc)(char*);
      char *arg;

      httpFunc = (void(*)(char*))flows->pluginStatus.pluginPtr->httpFunct;

      if(strlen(url) == strlen(flows->pluginStatus.pluginPtr->pluginURLname))
	arg = "";
      else
	arg = &url[strlen(flows->pluginStatus.pluginPtr->pluginURLname)+1];

      /* traceEvent(TRACE_INFO, "Found %s [%s]\n", 
	 flows->pluginStatus.pluginPtr->pluginURLname, arg); */
      httpFunc(arg);
      return(1);
    } else
      flows = flows->next;

  return(0); /* Plugin not found */
}

/* ******************* */

#if (defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(HPUX) || defined(AIX)
void loadPlugin(char* dirName, char* pluginName) {
  char pluginPath[256];
  char tmpBuf[BUF_SIZE];
  int i;
#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
  shl_t pluginPtr;
#else
#ifndef WIN32
  void *pluginPtr;
#endif
#endif
#ifndef WIN32
  void *pluginEntryFctnPtr;
#endif
  PluginInfo* pluginInfo;
  
  int rc;
#ifndef WIN32
  PluginInfo* (*pluginJumpFunc)();
#endif
  FlowFilterList *newFlow;

  snprintf(pluginPath, sizeof(pluginPath), "%s/%s", dirName, pluginName);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Loading plugin '%s'...\n", pluginPath);
#endif

#ifndef STATIC_PLUGIN
#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
  /* Load the library */
  pluginPtr = shl_load(pluginPath, BIND_IMMEDIATE|BIND_VERBOSE|BIND_NOSTART ,0L);
#else
#ifdef AIX
  pluginPtr = load(pluginName, 1, dirName); /* Load the library */
#else
  pluginPtr = dlopen(pluginPath, RTLD_NOW /* RTLD_LAZY */); /* Load the library */
#endif /* AIX */
#endif /* HPUX  */

  if(pluginPtr == NULL) {
#if HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
    traceEvent(TRACE_WARNING, 
	       "WARNING: unable to load plugin '%s'\n[%s]\n", 
	       pluginPath, strerror(errno));
#else
    traceEvent(TRACE_WARNING, 
	       "WARNING: unable to load plugin '%s'\n[%s]\n", 
	       pluginPath, dlerror());
#endif /* HPUX */
    return;
  }

#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
  if(shl_findsym(&pluginPtr ,PLUGIN_ENTRY_FCTN_NAME,
		 TYPE_PROCEDURE, &pluginEntryFctnPtr) == -1)
    pluginEntryFctnPtr = NULL;
#else
#ifdef AIX
  pluginEntryFctnPtr = pluginPtr;
#else
  pluginEntryFctnPtr = dlsym(pluginPtr, PLUGIN_ENTRY_FCTN_NAME);
#endif /* AIX */
#endif /* HPUX */

  if(pluginEntryFctnPtr == NULL) {
#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
    traceEvent(TRACE_WARNING, "\nWARNING: unable to local plugin '%s' entry function [%s] \n",
	       pluginPath, strerror(errno));
#else
#ifdef WIN32
    traceEvent(TRACE_WARNING, "WARNING: unable to local plugin '%s' entry function [%li]\n", 
	       pluginPath, GetLastError());
#else
    traceEvent(TRACE_WARNING, "WARNING: unable to local plugin '%s' entry function [%s]\n",
	       pluginPath, dlerror());
#endif /* WIN32 */
#endif /* HPUX */
    return;
  }

  pluginJumpFunc = (PluginInfo*(*)())pluginEntryFctnPtr;
  pluginInfo = pluginJumpFunc();
#else /* STATIC_PLUGIN */

  if(strcmp(pluginName, "icmpPlugin") == 0)
    pluginInfo = icmpPluginEntryFctn();
  else if(strcmp(pluginName, "arpPlugin") == 0)
    pluginInfo = arpPluginEntryFctn();
  else if(strcmp(pluginName, "nfsPlugin") == 0)
    pluginInfo = nfsPluginEntryFctn();
  else if(strcmp(pluginName, "wapPlugin") == 0)
    pluginInfo = wapPluginEntryFctn();
  else if(strcmp(pluginName, "ntopRmon") == 0)
    pluginInfo = rmonPluginEntryFctn();
  else if(strcmp(pluginName, "remoteInterface") == 0)
    pluginInfo = remIntPluginEntryFctn();  
  else
    pluginInfo = NULL;

#endif /* STATIC_PLUGIN */


  if(pluginInfo == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: %s call of plugin '%s' failed.\n",
	       PLUGIN_ENTRY_FCTN_NAME, pluginPath);
    return;
  }

  newFlow = (FlowFilterList*)calloc(1, sizeof(FlowFilterList));

  if(newFlow == NULL) {
    traceEvent(TRACE_ERROR, "Fatal error: not enough memory. Bye!\n");
    exit(-1);
  } else {
    newFlow->flowName = strdup(pluginInfo->pluginName);

    if((pluginInfo->bpfFilter == NULL)
       || (pluginInfo->bpfFilter[0] == '\0')) {
      /*
	traceEvent(TRACE_WARNING, "WARNING: plugin '%s' has an empty BPF filter.\n",
	pluginPath);
      */
      for(i=0; i<numDevices; i++)
	newFlow->fcode[i].bf_insns = NULL;
    } else {
      strncpy(tmpBuf, pluginInfo->bpfFilter, sizeof(tmpBuf));

      for(i=0; i<numDevices; i++) {
#ifdef DEBUG
	traceEvent(TRACE_INFO, "Compiling filter '%s' on device %s\n", 
		   tmpBuf, device[i].name);
#endif
	rc = pcap_compile(device[i].pcapPtr, 
			  &newFlow->fcode[i], tmpBuf, 1, 
			  device[i].netmask.s_addr);
      
	if(rc < 0) {
	  traceEvent(TRACE_INFO, 
		     "WARNING: plugin '%s' contains a wrong filter specification\n"
		     "         \"%s\" on interface %s (%s).\n"
		     "         This plugin has been discarded.\n",
		     pluginPath, 
		     pluginInfo->bpfFilter, 
		     device[i].name,
		     pcap_geterr((device[i].pcapPtr)));
	  free(newFlow);
	  return;
	}
      }
    }

    newFlow->pluginStatus.pluginPtr  = pluginInfo;
    newFlow->pluginStatus.activePlugin = pluginInfo->activeByDefault;
    newFlow->next = flowsList;
    flowsList = newFlow;
    /* traceEvent(TRACE_INFO, "Adding: %s\n", pluginInfo->pluginName); */
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Plugin '%s' loaded succesfully.\n", pluginPath);
#endif
}

/* ******************* */

void loadPlugins() {
#ifndef WIN32
  char dirPath[256];
  struct dirent* dp;
  int idx;
  DIR* directoryPointer=NULL;
#else
#ifndef WIN32
  char tmpStr[512], _tmpnam[255];
  FILE *fd;
  int rc;
#endif
#endif
  
  traceEvent(TRACE_INFO, "Loading plugins (if any)...\n");
  
#ifndef STATIC_PLUGIN
  for(idx=0; dirs[idx] != NULL; idx++) {
    snprintf(dirPath, sizeof(dirPath), "%s/plugins", dirs[idx]);

    directoryPointer = opendir(dirPath);

    if(directoryPointer != NULL)
      break;
  }

  if(directoryPointer == NULL) {
    traceEvent(TRACE_WARNING, 
	       "WARNING: Unable to find the plugins/ directory.\n");
    return;
  } else
    traceEvent(TRACE_INFO, "Searching plugins in %s\n", dirPath);

  while((dp = readdir(directoryPointer)) != NULL) {
    if(dp->d_name[0] == '.')
      continue;
    else if(strlen(dp->d_name) < strlen(PLUGIN_EXTENSION))
      continue;
    else if(strcmp(&dp->d_name[strlen(dp->d_name)-strlen(PLUGIN_EXTENSION)],
		   PLUGIN_EXTENSION))
      continue;
    
    loadPlugin(dirPath, dp->d_name);
  }

  closedir(directoryPointer);
#else /* STATIC_PLUGIN */
  loadPlugin(NULL, "icmpPlugin");
  loadPlugin(NULL, "arpPlugin");
  loadPlugin(NULL, "nfsPlugin");
  loadPlugin(NULL, "wapPlugin");
  loadPlugin(NULL, "remoteInterface");
  loadPlugin(NULL, "rmonPlugin");
#endif /* STATIC_PLUGIN */
}

/* ******************* */

void unloadPlugins() {
  FlowFilterList *flows = flowsList;

  traceEvent(TRACE_INFO, "Unloading plugins (if any)...\n");

  while(flows != NULL) {
    if(flows->pluginStatus.pluginPtr != NULL) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "Unloading plugin '%s'...\n",
		 flows->pluginStatus.pluginPtr->pluginName);
#endif
      if(flows->pluginStatus.pluginPtr->termFunc != NULL) {
	void (*termFunc)();

	termFunc = (void(*)())flows->pluginStatus.pluginPtr-> termFunc;
	termFunc();
      }

#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
      shl_unload((shl_t)flows->pluginStatus.pluginPtr);
#else
#ifdef WIN32
      FreeLibrary((HANDLE)flows->pluginStatus.pluginPtr);
#else
#ifdef AIX
      unload(flows->pluginStatus.pluginPtr);
#else
      dlclose(flows->pluginStatus.pluginPtr);
#endif /* AIX */
#endif /* WIN32 */
#endif /* HPUX */
      flows->pluginStatus.pluginPtr = NULL;
    }
    flows = flows->next;
  }
}

#endif /* defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H) */

/* ************************************* */

#ifdef AIX

char* dlerror() {
  char *errMsg[768];
  static char tmpStr[256];

  if(loadquery(L_GETMESSAGES, &errMsg, 768) != -1) {
    int i, j, errCode;
    char* errName;

    for(i=0; errMsg[i] != NULL; i++){
      errCode=atoi(errMsg[i]);
      errName = "";
	  
      for(j=1; errMsg[i][j] != '\0'; j++)
	if(errMsg[i][j] != ' ') {
	  errName = &errMsg[i][j];
	  break;
	}
	  
      switch(errCode) {
	/* sys/ldr.h */
      case 1:
	return("Too many errors, rest skipped");
	break;
      case 2:
	snprintf(tmpStr, sizeof(tmpStr), "Can't load library [%s]", errName);
	break;
      case 3:
	snprintf(tmpStr, sizeof(tmpStr), "Can't find symbol in library [%s]", errName);
	break;
      case 4:
	return("Rld data offset or symbol index out of range or bad relocation type");
	break;
      case 5:
	snprintf(tmpStr, sizeof(tmpStr), "File not valid, executable xcoff [%s]", errName);
	return(tmpStr);
	break;
      case 6:
	snprintf(tmpStr, sizeof(tmpStr), "The errno associated with the failure if not ENOEXEC,"
		" it indicates the underlying error, such as no memory [%s][errno=%d]", 
		errName, errno);
	return(tmpStr);
	break;
      case 7:
	snprintf(tmpStr, sizeof(tmpStr), "Member requested from a file which is not an archive or does not"
		"contain the member [%s]", errName);
	return(tmpStr);
	break;
      case 8:
	snprintf(tmpStr, sizeof(tmpStr), "Symbol type mismatch [%s]", errName);
	return(tmpStr);
	break;
      case 9:
	return("Text alignment in file is wrong");
	break;
      case 10:
	return("Insufficient permission to create a loader domain");
	break;
      case 11:
	return("Insufficient permission to add entries to a loader domain");
	break;
      default:
	snprintf(tmpStr, sizeof(tmpStr), "Unknown error [%d]", errCode);
	return(tmpStr);
      }
    }
  }
}

#endif /* AIX */
