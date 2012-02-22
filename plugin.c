/*
 *  Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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

#ifdef MAKE_STATIC_PLUGIN
extern PluginInfo* sflowPluginEntryFctn(void);
extern PluginInfo* rrdPluginEntryFctn(void);
extern PluginInfo* netflowPluginEntryFctn(void);
#endif

/* ******************* */

#if (defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(DARWIN)
static void loadPlugin(char* dirName, char* pluginName) {
  char pluginPath[256];
  char tmpBuf[LEN_GENERAL_WORK_BUFFER];
  int i;
#ifndef WIN32
  void *pluginPtr = NULL;
  void *pluginEntryFctnPtr;
#endif
  PluginInfo* pluginInfo;
  char key[64], value[16];
  int rc;
#ifndef WIN32
  PluginInfo* (*pluginJumpFunc)(void);
#endif
  FlowFilterList *newFlow,
    *work, *prev = NULL;

  safe_snprintf(__FILE__, __LINE__, pluginPath, sizeof(pluginPath), "%s/%s", dirName != NULL ? dirName : ".", pluginName);

  traceEvent(CONST_TRACE_NOISY, "Loading plugin '%s'", pluginPath);

#ifndef MAKE_STATIC_PLUGIN
  pluginPtr = (void*)dlopen(pluginPath, RTLD_NOW /* RTLD_LAZY */); /* Load the library */

  if(pluginPtr == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Unable to load plugin '%s'", pluginPath);
    traceEvent(CONST_TRACE_WARNING, "Message is '%s'", dlerror());
    return;
  }

  pluginEntryFctnPtr = (void*)dlsym(pluginPtr, CONST_PLUGIN_ENTRY_FCTN_NAME);

  if(pluginEntryFctnPtr == NULL) {
#ifdef WIN32
    traceEvent(CONST_TRACE_WARNING, "Unable to locate plugin '%s' entry function [%li]", 
	       pluginPath, GetLastError());
#else
    traceEvent(CONST_TRACE_WARNING, "Unable to locate plugin '%s' entry function [%s]",
	       pluginPath, dlerror());
#endif /* WIN32 */
    return;
  }

  pluginJumpFunc = (PluginInfo*(*)(void))pluginEntryFctnPtr;
  pluginInfo = pluginJumpFunc();
#else /* MAKE_STATIC_PLUGIN */

 if(strcmp(pluginName, "sflowPlugin") == 0)
    pluginInfo = sflowPluginEntryFctn();
  else if(strcmp(pluginName, "netflowPlugin") == 0)
    pluginInfo = netflowPluginEntryFctn();
  else if(strcmp(pluginName, "rrdPlugin") == 0)
    pluginInfo = rrdPluginEntryFctn();
  else
    pluginInfo = NULL;

#endif /* MAKE_STATIC_PLUGIN */

  if(pluginInfo == NULL) {
    traceEvent(CONST_TRACE_WARNING, "%s call of plugin '%s' failed",
	       CONST_PLUGIN_ENTRY_FCTN_NAME, pluginPath);
    return;
  }

  if((pluginInfo->pluginNtopVersion == NULL)
     || strcmp(pluginInfo->pluginNtopVersion, VERSION)) {
    traceEvent(CONST_TRACE_WARNING, "Plugin '%s' discarded: compiled for a different ntop version", pluginName);
    traceEvent(CONST_TRACE_WARNING, "Expected ntop version '%s', actual plugin ntop version '%s'.",
	       pluginInfo->pluginNtopVersion == NULL ? "??" : pluginInfo->pluginNtopVersion,
	       VERSION);
    return;
  }

  newFlow = (FlowFilterList*)calloc(1, sizeof(FlowFilterList));
  
  if(newFlow == NULL) {
    traceEvent(CONST_TRACE_FATALERROR, "Not enough memory for plugin flow filter - aborting");
    exit(42); /* Just in case */
  } else {
    newFlow->fcode = (struct bpf_program*)calloc(MAX_NUM_DEVICES, sizeof(struct bpf_program));
    newFlow->flowName = strdup(pluginInfo->pluginName);

    if((pluginInfo->bpfFilter == NULL) || (pluginInfo->bpfFilter[0] == '\0')) {
      if(pluginInfo->pluginFunct != NULL)
	traceEvent(CONST_TRACE_NOISY, "Note: Plugin '%s' has an empty BPF filter (this may not be wrong)", 
		   pluginPath);
      for(i=0; i<myGlobals.numDevices; i++)
	newFlow->fcode[i].bf_insns = NULL;
    } else {
      strncpy(tmpBuf, pluginInfo->bpfFilter, sizeof(tmpBuf));
      tmpBuf[sizeof(tmpBuf)-1] = '\0'; /* just in case bpfFilter is too long... */
      
      for(i=0; i<myGlobals.numDevices; i++) 
	if((!myGlobals.device[i].virtualDevice)
	   && (!myGlobals.device[i].dummyDevice)
	   && (myGlobals.device[i].pcapPtr)
	   ) {
	  traceEvent(CONST_TRACE_NOISY, "Compiling filter '%s' on interface %s", 
		     tmpBuf, myGlobals.device[i].name);
	  rc = pcap_compile(myGlobals.device[i].pcapPtr, 
			    &newFlow->fcode[i], tmpBuf, 1, 
			    myGlobals.device[i].netmask.s_addr);
      
         if(rc < 0) {
	    traceEvent(CONST_TRACE_WARNING, "Plugin '%s' contains a wrong filter specification",
		       pluginPath);
            traceEvent(CONST_TRACE_WARNING, "    \"%s\" on interface %s (%s)",
		       pluginInfo->bpfFilter, 
		       myGlobals.device[i].name,
		       pcap_geterr((myGlobals.device[i].pcapPtr)));
            traceEvent(CONST_TRACE_INFO, "The filter has been discarded");
	    free(newFlow);
	    return;
	  }
	}
    }

#ifndef WIN32
    newFlow->pluginStatus.pluginMemoryPtr = pluginPtr;
#endif
    newFlow->pluginStatus.pluginPtr       = pluginInfo;

    safe_snprintf(__FILE__, __LINE__, key, sizeof(key), "pluginStatus.%s", pluginInfo->pluginName);

    if(fetchPrefsValue(key, value, sizeof(value)) == -1) {
      storePrefsValue(key, pluginInfo->activeByDefault ? "1" : "0");
      newFlow->pluginStatus.activePlugin = pluginInfo->activeByDefault;
    } else {
      if(strcmp(value, "1") == 0) 
	newFlow->pluginStatus.activePlugin = 1;
      else
	newFlow->pluginStatus.activePlugin = 0;
    }

    /* Find where to insert */
    if((work = myGlobals.flowsList) == NULL) {
      myGlobals.flowsList = newFlow;
    } else {
      while((work != NULL) && (strcasecmp(newFlow->flowName, work->flowName) > 0)) {
        prev = work;
        work = work->next;
      }
      if (work == myGlobals.flowsList) {
        /* 1st in chain */
        newFlow->next = myGlobals.flowsList;
        myGlobals.flowsList = newFlow;
      } else {
        /* Insert in chain */
        newFlow->next = prev->next;
        prev->next = newFlow;
      }
    }

    /* traceEvent(CONST_TRACE_INFO, "Adding: %s", pluginInfo->pluginName); */
  }

#ifdef PLUGIN_DEBUG
  traceEvent(CONST_TRACE_INFO, "Plugin '%s' loaded succesfully.", pluginPath);
#endif
}

/* ******************* */

void loadPlugins(void) {
#ifndef WIN32
  char dirPath[256];
  struct dirent* dp;
  int idx;
  DIR* directoryPointer=NULL;
#endif

  if(static_ntop) return;
  
#ifndef MAKE_STATIC_PLUGIN
  for(idx=0; myGlobals.pluginDirs[idx] != NULL; idx++) {
    safe_snprintf(__FILE__, __LINE__, dirPath, sizeof(dirPath), "%s", myGlobals.pluginDirs[idx]);

    directoryPointer = opendir(dirPath);

    if(directoryPointer != NULL)
      break;
  }

  if(directoryPointer == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Unable to find the plugins/ directory");
    traceEvent(CONST_TRACE_INFO, "ntop continues OK, but without any plugins");
    return;
  } else
    traceEvent(CONST_TRACE_INFO, "Searching for plugins in %s", dirPath);

  while((dp = readdir(directoryPointer)) != NULL) {
    if(dp->d_name[0] == '.')
      continue;
    else if(strlen(dp->d_name) < strlen(CONST_PLUGIN_EXTENSION))
      continue;
    else if(strcmp(&dp->d_name[strlen(dp->d_name)-strlen(CONST_PLUGIN_EXTENSION)],
		   CONST_PLUGIN_EXTENSION))
      continue;
    
    loadPlugin(dirPath, dp->d_name);
  }

  closedir(directoryPointer);
#else /* MAKE_STATIC_PLUGIN */
  loadPlugin(NULL, "sflowPlugin");
  loadPlugin(NULL, "netflowPlugin");
  loadPlugin(NULL, "rrdPlugin");
#endif /* MAKE_STATIC_PLUGIN */
}

/* ******************* */

void unloadPlugins(void) {
  FlowFilterList *flows = myGlobals.flowsList;

  if(static_ntop) return;

  traceEvent(CONST_TRACE_INFO, "PLUGIN_TERM: Unloading plugins (if any)");

  while(flows != NULL) {
    if(flows->pluginStatus.pluginMemoryPtr != NULL) {
#ifdef PLUGIN_DEBUG
      traceEvent(CONST_TRACE_INFO, "PLUGIN_TERM: Unloading plugin '%s'",
		 flows->pluginStatus.pluginPtr->pluginName);
#endif
      if((flows->pluginStatus.pluginPtr->termFunct != NULL)
	 && (flows->pluginStatus.activePlugin))
	flows->pluginStatus.pluginPtr->termFunct(1 /* term ntop */);

#ifndef MAKE_STATIC_PLUGIN
#ifdef WIN32
      FreeLibrary((HANDLE)flows->pluginStatus.pluginMemoryPtr);
#else
      dlclose(flows->pluginStatus.pluginMemoryPtr);
#endif /* WIN32 */
#endif
      flows->pluginStatus.pluginPtr       = NULL;
      flows->pluginStatus.pluginMemoryPtr = NULL;
    }

    flows = flows->next;
  }
}

#endif /* defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H) */

/* ******************************* */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

void startPlugins(void) {
  FlowFilterList *flows = myGlobals.flowsList;

  if(static_ntop) return;

  traceEvent(CONST_TRACE_INFO, "Calling plugin start functions (if any)");

  while(flows != NULL) {
    if(flows->pluginStatus.pluginPtr != NULL) {
      traceEvent(CONST_TRACE_NOISY, "Starting '%s'",
		 flows->pluginStatus.pluginPtr->pluginName);
      if((flows->pluginStatus.pluginPtr->startFunct != NULL)
	 && (flows->pluginStatus.activePlugin)) {
	int rc = flows->pluginStatus.pluginPtr->startFunct();
	if(rc != 0)
	  flows->pluginStatus.activePlugin = 0;
      }
    }
    flows = flows->next;
  }
}

/* ******************* */

void handlePluginHostCreationDeletion(HostTraffic *el, u_short deviceId, u_char host_creation) {
  FlowFilterList *flows = myGlobals.flowsList;

  while(flows != NULL) {
    if(flows->pluginStatus.pluginMemoryPtr != NULL) {
      if(flows->pluginStatus.activePlugin 
	 && (flows->pluginStatus.pluginPtr->crtDltFunct != NULL))
	flows->pluginStatus.pluginPtr->crtDltFunct(el, deviceId, host_creation);
    }
    
    flows = flows->next;
  }
}

