/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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
extern PluginInfo* icmpPluginEntryFctn(void);
extern PluginInfo* nfsPluginEntryFctn(void);
extern PluginInfo* sflowPluginEntryFctn(void);
extern PluginInfo* rrdPluginEntryFctn(void);
/* rrd never made it into the code base */
extern PluginInfo* netflowPluginEntryFctn(void);
#endif

/* ******************* */

#ifdef AIX

static char* dlerror() {
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
	if(snprintf(tmpStr, sizeof(tmpStr), "Can't load library [%s]", errName) < 0) 
	  BufferTooShort();
	break;
      case 3:
	if(snprintf(tmpStr, sizeof(tmpStr), "Can't find symbol in library [%s]", errName) < 0) 
	  BufferTooShort();
	break;
      case 4:
	return("Rld data offset or symbol index out of range or bad relocation type");
	break;
      case 5:
	if(snprintf(tmpStr, sizeof(tmpStr), "File not valid, executable xcoff [%s]", errName) < 0)
	  BufferTooShort();
	return(tmpStr);
	break;
      case 6:
	if(snprintf(tmpStr, sizeof(tmpStr), "The errno associated with the failure if not ENOEXEC,"
		" it indicates the underlying error, such as no memory [%s][errno=%d]", 
		errName, errno) < 0) BufferTooShort();
	return(tmpStr);
	break;
      case 7:
	if(snprintf(tmpStr, sizeof(tmpStr), 
		    "Member requested from a file which is not an archive or does not"
		    "contain the member [%s]", errName) < 0) BufferTooShort();
	return(tmpStr);
	break;
      case 8:
	if(snprintf(tmpStr, sizeof(tmpStr), "Symbol type mismatch [%s]", errName) < 0)
	  BufferTooShort();
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
	if(snprintf(tmpStr, sizeof(tmpStr), "Unknown error [%d]", errCode) < 0) 
	  BufferTooShort();
	return(tmpStr);
      }
    }
  }
}

#endif /* AIX */

/* ******************* */

#if (defined(HAVE_DIRENT_H) && defined(HAVE_DLFCN_H)) || defined(WIN32) || defined(DARWIN)
static void loadPlugin(char* dirName, char* pluginName) {
  char pluginPath[256];
  char tmpBuf[LEN_GENERAL_WORK_BUFFER];
  int i;
#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
  shl_t pluginPtr;
#else
#ifndef WIN32
  void *pluginPtr = NULL;
#endif
#endif
#ifndef WIN32
  void *pluginEntryFctnPtr;
#endif
  PluginInfo* pluginInfo;
  char key[64], value[16];
  int rc;
#ifndef WIN32
  PluginInfo* (*pluginJumpFunc)();
#endif
  FlowFilterList *newFlow;

  if(snprintf(pluginPath, sizeof(pluginPath), "%s/%s", dirName != NULL ? dirName : ".", pluginName) < 0)
    BufferTooShort();

  traceEvent(CONST_TRACE_NOISY, "Loading plugin '%s'", pluginPath);

#ifndef MAKE_STATIC_PLUGIN
#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
  /* Load the library */
  pluginPtr = shl_load(pluginPath, BIND_IMMEDIATE|BIND_VERBOSE|BIND_NOSTART ,0L);
#else
#ifdef AIX
  pluginPtr = load(pluginName, 1, dirName); /* Load the library */
#else
  pluginPtr = (void*)dlopen(pluginPath, RTLD_NOW /* RTLD_LAZY */); /* Load the library */
#endif /* AIX */
#endif /* HPUX  */

  if(pluginPtr == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Unable to load plugin '%s'", pluginPath);
    traceEvent(CONST_TRACE_WARNING, "Message is '%s'", 
#if HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
	                            strerror(errno)
#else
	                            dlerror()
#endif
              );
    return;
  }

#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
  if(shl_findsym(&pluginPtr ,CONST_PLUGIN_ENTRY_FCTN_NAME,
		 TYPE_PROCEDURE, &pluginEntryFctnPtr) == -1)
    pluginEntryFctnPtr = NULL;
#else
#ifdef AIX
  pluginEntryFctnPtr = pluginPtr;
#else
  pluginEntryFctnPtr = (void*)dlsym(pluginPtr, CONST_PLUGIN_ENTRY_FCTN_NAME);
#endif /* AIX */
#endif /* HPUX */

  if(pluginEntryFctnPtr == NULL) {
#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
    traceEvent(CONST_TRACE_WARNING, "Unable to locate plugin '%s' entry function [%s]",
	       pluginPath, strerror(errno));
#else
#ifdef WIN32
    traceEvent(CONST_TRACE_WARNING, "Unable to locate plugin '%s' entry function [%li]", 
	       pluginPath, GetLastError());
#else
    traceEvent(CONST_TRACE_WARNING, "Unable to locate plugin '%s' entry function [%s]",
	       pluginPath, dlerror());
#endif /* WIN32 */
#endif /* HPUX */
    return;
  }

  pluginJumpFunc = (PluginInfo*(*)())pluginEntryFctnPtr;
  pluginInfo = pluginJumpFunc();
#else /* MAKE_STATIC_PLUGIN */

  if(strcmp(pluginName, "icmpPlugin") == 0)
    pluginInfo = icmpPluginEntryFctn();
  else if(strcmp(pluginName, "nfsPlugin") == 0)
    pluginInfo = nfsPluginEntryFctn();
  else if(strcmp(pluginName, "sflowPlugin") == 0)
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

  newFlow = (FlowFilterList*)calloc(1, sizeof(FlowFilterList));
  
  if(newFlow == NULL) {
    traceEvent(CONST_TRACE_FATALERROR, "Not enough memory for plugin flow filter - aborting");
    exit(-1);
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
	if(!myGlobals.device[i].virtualDevice) {
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

    if(snprintf(key, sizeof(key), "pluginStatus.%s", pluginInfo->pluginName) < 0)
      BufferTooShort();

    if(fetchPrefsValue(key, value, sizeof(value)) == -1) {
      storePrefsValue(key, pluginInfo->activeByDefault ? "1" : "0");
      newFlow->pluginStatus.activePlugin = pluginInfo->activeByDefault;
    } else {
      if(strcmp(value, "1") == 0) 
	newFlow->pluginStatus.activePlugin = 1;
      else
	newFlow->pluginStatus.activePlugin = 0;
    }

    newFlow->next = myGlobals.flowsList;
    myGlobals.flowsList = newFlow;
    /* traceEvent(CONST_TRACE_INFO, "Adding: %s\n", pluginInfo->pluginName); */
  }

#ifdef PLUGIN_DEBUG
  traceEvent(CONST_TRACE_INFO, "Plugin '%s' loaded succesfully.\n", pluginPath);
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
  
#ifndef MAKE_STATIC_PLUGIN
  for(idx=0; myGlobals.pluginDirs[idx] != NULL; idx++) {
    if(snprintf(dirPath, sizeof(dirPath), "%s", myGlobals.pluginDirs[idx]) < 0) 
      BufferTooShort();

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
  loadPlugin(NULL, "icmpPlugin");
  loadPlugin(NULL, "nfsPlugin");
  loadPlugin(NULL, "sflowPlugin");
  loadPlugin(NULL, "netflowPlugin");
  loadPlugin(NULL, "rrdPlugin");
#endif /* MAKE_STATIC_PLUGIN */
}

/* ******************* */

void unloadPlugins(void) {
  FlowFilterList *flows = myGlobals.flowsList;

  traceEvent(CONST_TRACE_INFO, "PLUGIN_TERM: Unloading plugins (if any)");

  while(flows != NULL) {
    if(flows->pluginStatus.pluginMemoryPtr != NULL) {
#ifdef PLUGIN_DEBUG
      traceEvent(CONST_TRACE_INFO, "PLUGIN_TERM: Unloading plugin '%s'",
		 flows->pluginStatus.pluginPtr->pluginName);
#endif
      if((flows->pluginStatus.pluginPtr->termFunct != NULL)
	 && (flows->pluginStatus.activePlugin))
	flows->pluginStatus.pluginPtr->termFunct();

#ifdef HPUX /* Courtesy Rusetsky Dmitry <dimania@mail.ru> */
      shl_unload((shl_t)flows->pluginStatus.pluginMemoryPtr);
#else
#ifdef WIN32
      FreeLibrary((HANDLE)flows->pluginStatus.pluginMemoryPtr);
#else
#ifdef AIX
      unload(flows->pluginStatus.pluginMemoryPtr);
#else
      dlclose(flows->pluginStatus.pluginMemoryPtr);
#endif /* AIX */
#endif /* WIN32 */
#endif /* HPUX */
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

/* ************************************* */


