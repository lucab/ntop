/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 *         Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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

/* Prevent expansion of leaks.h */
#define _LEAKS_H_

#include "ntop.h"

/* #define DEBUG */
/* #define USE_GC */

/* ****************************************** *
 * Complexity: We have routines here which    *
 *  (in coordination with globals-core.h)     *
 *  override the default glibc routines.      *
 *                                            *
 *  We call them 'safer' because the do some  *
 *  reasonability and error checking.         *
 *                                            *
 * If we aren't building the safer set, we    *
 *  have other choices, depending upon        *
 *  MEMORY_DEBUG (nothing, i.e. the default   *
 *  and/or various dropins) and our own       *
 *  'watching' routines.                      *
 *                                            *
 * ****************************************** */

#ifdef MAKE_WITH_SAFER_ROUTINES

/* ***************************************************** */

static void stopcap(void) {
  traceEvent(CONST_TRACE_WARNING, "ntop packet capture STOPPED");
  traceEvent(CONST_TRACE_INFO, "NOTE: ntop web server remains up");
  traceEvent(CONST_TRACE_INFO, "NOTE: Shutdown gracefully and restart with more memory");
  setRunState(FLAG_NTOPSTATE_STOPCAP);
}

#undef malloc /* just to be safe */

/* #define COUNT_MALLOCS 1 */

/* ***************************************************** */

void* ntop_safemalloc(unsigned int sz, char* file, int line) {
  void *thePtr;
#ifdef COUNT_MALLOCS
  static uint num_allocs = 0, tot_allocs = 0;
#endif

#ifdef DEBUG
  if((sz == 0) || (sz > 32768)) {
    traceEvent(CONST_TRACE_INFO, "DEBUG: malloc(%u) @ %s:%d", sz, file, line);
    if(sz == 0) sz = 8; /* 8 bytes is the minimal size ntop can allocate
                         * for doing things that make sense
                         */
  }
#endif

#ifndef USE_GC
  thePtr = malloc(sz);
#else
  thePtr = GC_malloc_atomic(sz);
#endif

#if COUNT_MALLOCS
  tot_allocs += sz, num_allocs++; traceEvent(CONST_TRACE_ERROR, "[num_allocs=%u][size=%u][total=%u]", num_allocs, sz, tot_allocs);
#endif

  if(thePtr == NULL) {
    traceEvent(CONST_TRACE_ERROR, "malloc(%u) @ %s:%d returned NULL [no more memory?]",
	       sz, file, line);
    if ((myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) &&
	(myGlobals.runningPref.disableStopcap != TRUE)) {
      stopcap();
    } /* else - just keep on trucking ... ouch */
  } else
    memset(thePtr, 0xee, sz); /* Fill it with garbage */

  return(thePtr);
}

/* ****************************************** */

/* Courtesy of Wies-Software <wies@wiessoft.de> */
#undef calloc /* just to be safe */
void* ntop_safecalloc(unsigned int c, unsigned int sz, char* file, int line) {  
  void *thePtr;
  
#ifdef DEBUG
  if((sz == 0) || (sz > 32768)) {
    traceEvent(CONST_TRACE_INFO, "DEBUG: called calloc(%u,%u) @ %s:%d",
	       c, sz, file, line);
  }
#endif
  
#ifndef USE_GC
  thePtr = calloc(c, sz);
#else
  thePtr = GC_malloc_atomic(c*sz);
#endif

  if(thePtr == NULL) {
    traceEvent(CONST_TRACE_ERROR, 
	       "calloc(%u,%u) @ %s:%d returned NULL [no more memory?]",
	       c, sz, file, line);
    if ( (myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) &&
         (myGlobals.runningPref.disableStopcap != TRUE) ) {
      stopcap();
    } /* else - just keep on trucking ... ouch */
  }
  
  return(thePtr);
}

/* ****************************************** */

/* Courtesy of Wies-Software <wies@wiessoft.de> */
#undef realloc /* just to be safe */
void* ntop_saferealloc(void* ptr, unsigned int sz, char* file, int line) {
  void *thePtr;
  
#ifdef DEBUG
  if((sz == 0) || (sz > 32768)) {
    traceEvent(CONST_TRACE_INFO, "DEBUG: called realloc(%p,%u) @ %s:%d",
	       ptr, sz, file, line);
  }
#endif
  
#ifndef USE_GC
  thePtr = realloc(ptr, sz);
#else
  thePtr = GC_realloc(ptr, sz);
#endif

  if(thePtr == NULL) {
    traceEvent(CONST_TRACE_ERROR, 
	       "realloc(%u) @ %s:%d returned NULL [no more memory?]",
	       sz, file, line);
    if ( (myGlobals.ntopRunState <= FLAG_NTOPSTATE_RUN) &&
         (myGlobals.runningPref.disableStopcap != TRUE) ) {
      stopcap();
    } /* else - just keep on trucking ... ouch */
  }

  return(thePtr);
}

/* ****************************************** */

#undef free /* just to be safe */
void ntop_safefree(void **ptr, char* file, int line) {

#ifdef DEBUG
  printf("DEBUG: free(%x) @ %s:%d\n", *ptr, file, line);
#endif

  if((ptr == NULL) || (*ptr == NULL)) {
    traceEvent(CONST_TRACE_WARNING, "free of NULL pointer @ %s:%d", 
	       file, line);
  } else {
    free(*ptr);
    *ptr = NULL;
  }
}

/* ****************************************** */

#undef strdup /* just to be safe */
char* ntop_safestrdup(char *ptr, char* file, int line) {  
  if(ptr == NULL) {
    traceEvent(CONST_TRACE_WARNING, "strdup of NULL pointer @ %s:%d", file, line);
#ifdef WIN32
	return(_strdup(""));
#else
	return(strdup(""));
#endif
  } else {
    char* theOut;
    int len = (int)strlen(ptr);
    
#ifndef USE_GC
    theOut = (char*)malloc((len+1)*sizeof(char));
#else
    theOut = (char*)GC_malloc_atomic((len+1)*sizeof(char));
#endif
    if(len > 0) strncpy(theOut, ptr, len);
    theOut[len] = '\0';
    
    return(theOut);
  }
}

#elif defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 1)

  /* mtrace()/muntrace() - use existing routines */

/* ****************************************** */
/* ****************************************** */

#elif defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 2)

  /* ElectricFence - use existing routines */

/* ****************************************** */
/* ****************************************** */

#elif defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)

  /* ntop custom monitor */

#undef malloc
#undef free
#undef strdup

/* gdbm routines */
#undef gdbm_firstkey
#undef gdbm_nextkey
#undef gdbm_fetch

typedef struct memoryBlock {
  void*               memoryLocation;       /* Malloc address              */
  size_t              blockSize;            /* Block size                  */
  char                programLocation[48];  /* Program address: file, line */
  struct memoryBlock* nextBlock;            /* Next memory block           */
  short alreadyTraced;
} MemoryBlock;

static MemoryBlock *theRoot = NULL;
static char tmpStr[255];
static int traceAllocs = 0;
static PthreadMutex leaksMutex;
static int inTraceEventTrapped = 0;

/* Forward declarations */
static void traceEventLeak(int eventTraceLevel, char* file, int line, char* format, ...);
unsigned int PrintMemoryBlocks(void);
size_t GimmePointerSize(void* thePtr);
int GimmePointerInfo(void* thePtr);
void myAddLeak(void* thePtr, int theLine, char* theFile);
void myRemoveLeak(void* thePtr, int theLine, char* theFile);

/* *************************************** */

/* This is a minimalist version of traceEvent() suitable for use in leak detection
 *
 *    We can not use the normal traceEvent() call because that might be
 *    where the fault lies.
 */
static void traceEventLeak(int eventTraceLevel, /* Ignored */
                           char* file, int line,
                           char * format, ...) {

  va_list va_ap;
  char bufF[LEN_GENERAL_WORK_BUFFER],
       bufMsg[LEN_GENERAL_WORK_BUFFER];

#ifdef WIN32
  /* If ntop is a Win32 service, we're done - we don't (yet) write to the
   * windows event logs and there's no console...
   */
  if(isNtopAservice) return;
#endif

  /* Our Lame attempt at deadlock prevention */
  if(inTraceEventTrapped == 1) return;

  inTraceEventTrapped=1;

  memset(bufF, 0, sizeof(bufF));
  memset(bufMsg, 0, sizeof(bufMsg));

  if(file == NULL)
    safe_snprintf(file, line, bufF, sizeof(bufF),
                  "LEAK: %s",
                  format);
  else
    safe_snprintf(file, line, bufF, sizeof(bufF),
                  "LEAK: %s [@%s:%d]",
                  format,
                  file, line);

  va_start (va_ap, format);

  vsnprintf(bufMsg, sizeof(bufMsg), bufF, va_ap);

  /* Strip a trailing return from bufMsg */
  if(bufMsg[strlen(bufMsg)-1] == '\n')
    bufMsg[strlen(bufMsg)-1] = 0;

  if(myGlobals.runningPref.instance != NULL)
    openlog(myGlobals.runningPref.instance, LOG_PID, myGlobals.runningPref.useSyslog);
  else
    openlog(CONST_DAEMONNAME, LOG_PID, myGlobals.runningPref.useSyslog);

  syslog(LOG_ERR, "%s", bufMsg);
  closelog();

  va_end (va_ap);

  inTraceEventTrapped=0;
}

/* *************************************** */

static void storePtr(void* ptr, int ptrLen, int theLine, char* theFile, int lockMutex) {
  MemoryBlock *tmpBlock;

  if(lockMutex)
    accessMutex(&leaksMutex, "storePtr");

  tmpBlock = (MemoryBlock*)malloc(sizeof(MemoryBlock));

  if(tmpBlock == NULL) {
    if(lockMutex)
      releaseMutex(&leaksMutex);
    traceEventLeak(CONST_FATALERROR_TRACE_LEVEL, 
                   theFile, theLine,
                   "malloc(%d) [tot=%u] not enough memory", ptrLen, myGlobals.allocatedMemory);
    exit(300);
  }
  
  tmpBlock->blockSize        = ptrLen;
  tmpBlock->memoryLocation   = ptr;
  tmpBlock->alreadyTraced    = 0;
  myGlobals.allocatedMemory += tmpBlock->blockSize;
      
  if(traceAllocs)
    traceEventLeak(CONST_INFO_TRACE_LEVEL,
                   theFile, theLine,
                   "malloc(%d) [tot=%u]", ptrLen, myGlobals.allocatedMemory);

  safe_snprintf(__FILE__, __LINE__, tmpBlock->programLocation, sizeof(tmpBlock->programLocation), 
		"%s@%d", theFile, theLine);
  tmpBlock->nextBlock = theRoot;
  theRoot = tmpBlock;
  if(lockMutex)
    releaseMutex(&leaksMutex);
}

/* ********************************* */

static void* myMalloc(size_t theSize, int theLine, char* theFile, int lockMutex) {
  void *theMem;

  theMem = malloc(theSize);
  memset(theMem, 0xee, theSize); /* Fill it with garbage */
  storePtr(theMem, theSize, theLine, theFile, lockMutex);
  return(theMem);
}

/* *************************************** */

static void* myCalloc(size_t numObj, size_t theSize, int theLine, char* theFile) {
  int numElems = numObj*theSize;
  void* thePtr = myMalloc(numElems, theLine, theFile, 1);

  if(thePtr != NULL)
    memset(thePtr, '\0', numElems);

  return(thePtr);
}

/* *************************************** */

static void* myRealloc(void* thePtr, size_t theSize, int theLine, char* theFile) {
  MemoryBlock *theScan, *lastPtr, *theNewPtr;
  
  accessMutex(&leaksMutex, "myRealloc");

  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL,
                   theFile, theLine,
                   "ERROR: realloc() - Ptr %p NOT allocated",
	           thePtr);
    releaseMutex(&leaksMutex);
    return(NULL);
  } else {    
    theNewPtr = myMalloc(theSize, theLine, theFile, 0);
      
    if(theSize > theScan->blockSize)
      memcpy(theNewPtr, thePtr, theScan->blockSize);
    else
      memcpy(theNewPtr, thePtr, theSize);
	
    free(theScan->memoryLocation);
      
    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);     

    releaseMutex(&leaksMutex);

    return(theNewPtr);
  }
}

/* *************************************** */

static void myFree(void **thePtr, int theLine, char* theFile) {
  MemoryBlock *theScan, *lastPtr;
  
  accessMutex(&leaksMutex, "myFree");

  theScan = theRoot;

  if((thePtr == NULL) || (*thePtr == NULL)) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL, theFile, theLine, "ERROR: free(NULL)", "");
    return;
  }
 
  while((theScan != NULL) && (theScan->memoryLocation != *thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL,
                   theFile, theLine,
                   "ERROR: free() - Ptr %p NOT allocated",
	           *thePtr);
    releaseMutex(&leaksMutex);
    return;
  } else {
    myGlobals.allocatedMemory -= theScan->blockSize;

    if(traceAllocs) 
      traceEventLeak(CONST_INFO_TRACE_LEVEL, theFile, theLine,
                     "free(%d)  [tot=%u]",
                     theScan->blockSize, myGlobals.allocatedMemory);

    free(theScan->memoryLocation);

    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);
    *thePtr = NULL;
  }

  releaseMutex(&leaksMutex);
}

/* *************************************** */

static char* myStrdup(char* theStr, int theLine, char* theFile) {
  char* theOut;
  int len = strlen(theStr);
  
  theOut = (char*)myMalloc((len+1), theLine, theFile, 1);
  strncpy(theOut, theStr, len);
  theOut[len] = '\0';

  return(theOut);
}

/* *************************************** */

void resetLeaks(void) {
  MemoryBlock *theScan;

  theScan = theRoot;
 
  while(theScan != NULL) {
    theScan->alreadyTraced = 1;
    theScan = theScan->nextBlock;
  }

  myGlobals.allocatedMemory = 0; /* Reset counter */
}

/* *************************************** */

unsigned int PrintMemoryBlocks(void) {
  MemoryBlock *theScan;
  int i = 0;
  unsigned int totMem = 0;

  theScan = theRoot;
 
  while(theScan != NULL) {
    MemoryBlock* tmp;

    if(!theScan->alreadyTraced) {
      traceEventLeak(CONST_INFO_TRACE_LEVEL, NULL, 0, 
                     "Block %5d (addr %p, size %4d): %s",
                     i++, 
		     theScan->memoryLocation,
                     theScan->blockSize,
                     theScan->programLocation);
      totMem += theScan->blockSize;
    }

    theScan->alreadyTraced = 1;
    tmp = theScan->memoryLocation;
    theScan = theScan->nextBlock;
  }

  traceEventLeak(CONST_INFO_TRACE_LEVEL, NULL, 0, "Total allocated memory: %u bytes", totMem);

  /* PrintMemoryBlocks(); */

  return(totMem);
}

/* *************************************** */

size_t GimmePointerSize(void* thePtr) {
  MemoryBlock *theScan;
  
  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr))
    theScan = theScan->nextBlock;

  if(theScan == NULL) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL, NULL, 0,
                   "ERROR: GimmePointerSize() - Ptr %p NOT allocated", thePtr);
    return(-1);
  } else
    return(theScan->blockSize);
}

/* *************************************** */

int GimmePointerInfo(void* thePtr) {
  MemoryBlock *theScan;
  
  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr))
    theScan = theScan->nextBlock;

  if(theScan == NULL) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL, NULL, 0, 
                   "ERROR: GimmePointerInfo() - Ptr %p NOT allocated", thePtr);
    return -1;
  } else {      
    traceEventLeak(CONST_TRACE_WARNING,
                   "Block (addr %p, size %d): %s",
                   theScan->memoryLocation, 
                   theScan->blockSize,
                   theScan->programLocation);
    return 0;
  }
}

/* *************************************** */

void myAddLeak(void* thePtr, int theLine, char* theFile) {
  MemoryBlock *tmpBlock;

  if(thePtr == NULL) 
    return;

  tmpBlock = (MemoryBlock*)malloc(sizeof(MemoryBlock));

  if(tmpBlock == NULL) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL, theFile, theLine,
                   "ERROR: myAddLeak() malloc() - not enough memory", ""); 
    return;
  }
  
  tmpBlock->blockSize = 0;
  tmpBlock->memoryLocation = thePtr;
  safe_snprintf(__FILE__, __LINE__, tmpBlock->programLocation, sizeof(tmpBlock->programLocation),
                "%s@%d", theFile, theLine);
  tmpBlock->nextBlock = theRoot;
  theRoot = tmpBlock;
}

/* *************************************** */

void myRemoveLeak(void* thePtr, int theLine, char* theFile) {
  MemoryBlock *theScan, *lastPtr;
  
  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEventLeak(CONST_ERROR_TRACE_LEVEL, theFile, theLine,
                   "ERROR: free() block error (Ptr %p NOT allocated)", thePtr); 
    return;
  } else {   
    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);
  }
}

/* *************************************** */

void initLeaks(void) {
  myGlobals.runningPref.useSyslog       = FLAG_SYSLOG_NONE;
  myGlobals.runningPref.traceLevel      = 999;
  myGlobals.allocatedMemory = 0;  

  createMutex(&leaksMutex);
}

/* *************************************** */

void termLeaks(void) {
  PrintMemoryBlocks();
  deleteMutex(&leaksMutex);
}

/* ************************************ */

void* ntop_malloc(unsigned int sz, char* file, int line) {

#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: malloc(%u) [%s] @ %s:%d", 
	     sz, formatBytes(myGlobals.allocatedMemory, 0, 
			     formatBuffer, sizeof(formatBuffer)), file, line);
#endif

  return(myMalloc(sz, line, file, 1));
}

/* ************************************ */

void* ntop_calloc(unsigned int c, unsigned int sz, char* file, int line) {
#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: calloc(%u) [%s] @ %s:%d", 
	     sz, formatBytes(myGlobals.allocatedMemory, 0, 
			     formatBuffer, sizeof(formatBuffer)), file, line);
#endif
  return(myCalloc(c, sz, line, file));
}

/* ************************************ */

void* ntop_realloc(void* ptr, unsigned int sz, char* file, int line) {  
#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: realloc(%u) [%s] @ %s:%d", 
	     sz, formatBytes(myGlobals.allocatedMemory, 0, 
			     formatBuffer, sizeof(formatBuffer)), file, line);
#endif  
  return(myRealloc(ptr, sz, line, file));
}

/* ************************************ */

char* ntop_strdup(char *str, char* file, int line) {
#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: strdup(%s) [%s] @ %s:%d", str, 
	     formatBytes(myGlobals.allocatedMemory, 0,
			 formatBuffer, sizeof(formatBuffer)), file, line);
#endif
  return(myStrdup(str, line, file));
}

/* ************************************ */

void ntop_free(void **ptr, char* file, int line) {
#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: free(%x) [%s] @ %s:%d", ptr, 
	     formatBytes(myGlobals.allocatedMemory, 0,
			 formatBuffer, sizeof(formatBuffer)), file, line);
#endif
  myFree(ptr, line, file);
}

#elif defined(MEMORY_DEBUG) 
#else
#endif /* MAKE_WITH_SAFER_ROUTINES / MEMORY_DEBUG */

/* ************************************************************************************** */
/* ************************************************************************************** */
/* ************************************************************************************** */

/* These replacment routines serialize gdbm access across threads
 *
 * They are here, vs. util.c so we can add implicit allocation tracking
 * when MEMORY_DEBUG is 3...
 */

#undef gdbm_firstkey
#undef gdbm_nextkey
#undef gdbm_fetch
#undef gdbm_delete
#undef gdbm_store
#undef gdbm_close

datum ntop_gdbm_firstkey(GDBM_FILE g, char* theFile, int theLine) {
  datum theData;

  memset(&theData, 0, sizeof(theData));

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_firstkey");

  theData = gdbm_firstkey(g);

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  if(theData.dptr != NULL) {
    storePtr(theData.dptr, theData.dsize, theLine, theFile, 1);
    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "gdbm_firstkey(%s:%d)", theFile, theLine);
  }
#endif /* MEMORY_DEBUG 3 */

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);

  return(theData);
}

/* ******************************************* */

datum ntop_gdbm_nextkey(GDBM_FILE g, datum d, char* theFile, int theLine) {
  datum theData;

  memset(&theData, 0, sizeof(theData));

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_nextkey");

  theData = gdbm_nextkey(g, d);

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  if(theData.dptr != NULL) {
    storePtr(theData.dptr, theData.dsize, theLine, theFile, 1);
    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "gdbm_nextkey(%s)", theData.dptr);
  }
#endif /* MEMORY_DEBUG 3 */

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);

  return(theData);
}

/* ******************************************* */

datum ntop_gdbm_fetch(GDBM_FILE g, datum d, char* theFile, int theLine) {
  datum theData;

  memset(&theData, 0, sizeof(theData));

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_fetch");

  theData = gdbm_fetch(g, d);

#if defined(MEMORY_DEBUG) && (MEMORY_DEBUG == 3)
  if(theData.dptr != NULL) {
    storePtr(theData.dptr, theData.dsize, theLine, theFile, 1);
    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "gdbm_fetch(%s) %x", theData.dptr, theData.dptr);
  }
#endif /* MEMORY_DEBUG 3 */

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);

  return(theData);
}

/* ******************************************* */

int ntop_gdbm_delete(GDBM_FILE g, datum d, char* theFile, int theLine) {
  int rc;

  if((d.dptr == NULL) || (d.dsize == 0)) {
    traceEvent(CONST_TRACE_WARNING, "Wrong data to delete passed to gdbm_delete()");
    return(-1);
  }

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_delete");

  rc = gdbm_delete(g, d);

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);

  return(rc);
}

/* ******************************************* */

int ntop_gdbm_store(GDBM_FILE g, datum d, datum v, int r, char* theFile, int theLine) {
  int rc;

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_store");

  rc = gdbm_store(g, d, v, r);

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);

  return(rc);
}

/* ******************************************* */

void ntop_gdbm_close(GDBM_FILE g, char* theFile, int theLine) {
  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    accessMutex(&myGlobals.gdbmMutex, "ntop_gdbm_close");

  gdbm_close(g);

  if(myGlobals.gdbmMutex.isInitialized == 1) /* Mutex not yet initialized ? */
    releaseMutex(&myGlobals.gdbmMutex);
}

/* ******************************************* */
/* ******************************************* */
