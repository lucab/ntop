/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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

#include "ntop.h"

/* #define USE_GC */

#ifdef MEMORY_DEBUG 

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
static int glib23xMessageWritten = 0;
#ifdef MEMORY_DEBUG
static PthreadMutex leaksMutex;
#endif


unsigned int PrintMemoryBlocks(); /* Forward declaration */

/* *************************************** */

static void storePtr(void* ptr, int ptrLen, int theLine, char* theFile, int lockMutex) {
  MemoryBlock *tmpBlock;

#if defined(CFG_MULTITHREADED)
  if(lockMutex) accessMutex(&leaksMutex, "storePtr");
#endif

  tmpBlock = (MemoryBlock*)malloc(sizeof(MemoryBlock));

  if(tmpBlock == NULL) {
#if defined(CFG_MULTITHREADED)
    if(lockMutex) releaseMutex(&leaksMutex);
#endif
    traceEvent(CONST_TRACE_FATALERROR, "malloc (not enough memory): %s, %d",  theFile, theLine);
    exit(-1);
  }
  
  tmpBlock->blockSize        = ptrLen;
  tmpBlock->memoryLocation   = ptr;
  tmpBlock->alreadyTraced    = 0;
  myGlobals.allocatedMemory += tmpBlock->blockSize;
      
  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "%s:%d.", theFile, theLine);

  if(traceAllocs)
    traceEvent(CONST_TRACE_INFO, "malloc(%d):%s  [tot=%u]", ptrLen, tmpStr, myGlobals.allocatedMemory);

  safe_snprintf(__FILE__, __LINE__, tmpBlock->programLocation, sizeof(tmpBlock->programLocation), 
		"%s", tmpStr);
  tmpBlock->nextBlock = theRoot;
  theRoot = tmpBlock;
#if defined(CFG_MULTITHREADED)
  if(lockMutex) releaseMutex(&leaksMutex);
#endif
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
  
#if defined(CFG_MULTITHREADED)
  accessMutex(&leaksMutex, "myRealloc");
#endif

  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Realloc error (Ptr %p NOT allocated): %s, %d", 
	       thePtr, theFile, theLine);
#if defined(CFG_MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif
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

#if defined(CFG_MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif

    return(theNewPtr);
  }
}

/* *************************************** */

static void myFree(void **thePtr, int theLine, char* theFile) {
  MemoryBlock *theScan, *lastPtr;
  
#if defined(CFG_MULTITHREADED)
  accessMutex(&leaksMutex, "myFree");
#endif

  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != *thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Free error (Ptr %p NOT allocated): %s, %d", 
	       *thePtr, theFile, theLine);
#if defined(CFG_MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif
    return;
  } else {
    myGlobals.allocatedMemory -= theScan->blockSize;

    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "free(%d):%s  [tot=%u]",
			       theScan->blockSize, theScan->programLocation, myGlobals.allocatedMemory);

    free(theScan->memoryLocation);

    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);
    *thePtr = NULL;
  }

#if defined(CFG_MULTITHREADED)
  releaseMutex(&leaksMutex);
#endif
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
      traceEvent(CONST_TRACE_INFO,"Block %5d (addr %p, size %4d): %s", i++, 
		 theScan->memoryLocation, theScan->blockSize, theScan->programLocation);
      totMem += theScan->blockSize;
    }

    theScan->alreadyTraced = 1;
    tmp = theScan->memoryLocation;
    theScan = theScan->nextBlock;
  }

  traceEvent(CONST_TRACE_INFO,"Total allocated memory: %u bytes", totMem);

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
    traceEvent(CONST_TRACE_WARNING, "GimmePointerSize error: Ptr %p NOT allocated", thePtr);
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
    traceEvent(CONST_TRACE_WARNING, "GimmePointerInfo error: Ptr %p NOT allocated", thePtr);
    return -1;
  } else {      
    traceEvent(CONST_TRACE_WARNING, "Block (addr %p, size %d): %s", theScan->memoryLocation, 
	       theScan->blockSize, theScan->programLocation);
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
    traceEvent(CONST_TRACE_WARNING, "Malloc error (not enough memory): %s, %d", 
	       theFile, theLine);
    return;
  }
  
  tmpBlock->blockSize = 0;
  tmpBlock->memoryLocation = thePtr;
  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr), "file %s, line %d.", theFile, theLine);
  safe_snprintf(__FILE__, __LINE__, tmpBlock->programLocation, sizeof(tmpBlock->programLocation), "%s", tmpStr);
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
    traceEvent(CONST_TRACE_WARNING, "Free  block error (Ptr %p NOT allocated): %s, %d", 
	       thePtr, theFile, theLine);
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
  myGlobals.useSyslog       = FLAG_SYSLOG_NONE;
  myGlobals.traceLevel      = 999;
  myGlobals.allocatedMemory = 0;  

#ifdef CFG_MULTITHREADED
  createMutex(&leaksMutex);
#endif
}

/* *************************************** */

void termLeaks(void) {
  PrintMemoryBlocks();
#ifdef CFG_MULTITHREADED
  deleteMutex(&leaksMutex);
#endif
}

/* ************************************ */

void* ntop_malloc(unsigned int sz, char* file, int line) {

#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: malloc(%d) [%s] @ %s:%d", 
	     sz, formatBytes(myGlobals.allocatedMemory, 0, 
			     formatBuffer, sizeof(formatBuffer)), file, line);
#endif

  return(myMalloc(sz, line, file, 1));
}

/* ************************************ */

void* ntop_calloc(unsigned int c, unsigned int sz, char* file, int line) {
#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: calloc(%d) [%s] @ %s:%d", 
	     sz, formatBytes(myGlobals.allocatedMemory, 0, 
			     formatBuffer, sizeof(formatBuffer)), file, line);
#endif
  return(myCalloc(c, sz, line, file));
}

/* ************************************ */

void* ntop_realloc(void* ptr, unsigned int sz, char* file, int line) {  
#ifdef DEBUG
  char formatBuffer[32];
  traceEvent(CONST_TRACE_INFO, "DEBUG: realloc(%d) [%s] @ %s:%d", 
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

/* ****************************************** */

datum ntop_gdbm_firstkey(GDBM_FILE g, char* theFile, int theLine) {
  datum theData = gdbm_firstkey(g);

  if(theData.dptr != NULL) {
    storePtr(theData.dptr, theData.dsize, theLine, theFile, 1);
    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "gdbm_firstkey(%s:%d)", theFile, theLine);
  }

  return(theData);
}

/* ******************************************* */

datum ntop_gdbm_nextkey(GDBM_FILE g, datum d, char* theFile, int theLine) {
  datum theData = gdbm_nextkey(g, d);

  if(theData.dptr != NULL) {
    storePtr(theData.dptr, theData.dsize, theLine, theFile, 1);
    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "gdbm_nextkey(%s)", theData.dptr);
  }

  return(theData);
}

/* ******************************************* */

datum ntop_gdbm_fetch(GDBM_FILE g, datum d, char* theFile, int theLine) {
  datum theData = gdbm_fetch(g, d);

  if(theData.dptr != NULL) {
    storePtr(theData.dptr, theData.dsize, theLine, theFile, 1);
    if(traceAllocs) traceEvent(CONST_TRACE_INFO, "gdbm_fetch(%s) %x", theData.dptr, theData.dptr);
  }

  return(theData);
}

/* ****************************************** */
/* ****************************************** */

#else /* MEMORY_DEBUG */

/* ****************************************** */
/* ****************************************** */

#undef malloc /* just to be safe */

void* ntop_safemalloc(unsigned int sz, char* file, int line) {
  void *thePtr;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: malloc(%d) @ %s:%d", sz, file, line);
#endif

#ifdef DEBUG
  if((sz == 0) || (sz > 32768)) {
    traceEvent(CONST_TRACE_INFO, "DEBUG: called malloc(%u) @ %s:%d", sz, file, line);
    if(sz == 0) sz = 8; /*
			  8 bytes is the minimal size ntop can allocate
			  for doing things that make sense
			*/
  }
#endif

#ifndef USE_GC
  thePtr = malloc(sz);
#else
  thePtr = GC_malloc_atomic(sz);
#endif

  if(thePtr == NULL) {
    traceEvent(CONST_TRACE_FATALERROR, "malloc(%d) @ %s:%d returned NULL [no more memory?]",
	       sz, file, line);
    if ((myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) &&
	(myGlobals.disableStopcap != TRUE)) {
      traceEvent(CONST_TRACE_WARNING, "ntop packet capture STOPPED");
      traceEvent(CONST_TRACE_INFO, "NOTE: ntop web server remains up");
      traceEvent(CONST_TRACE_INFO, "NOTE: Shutdown gracefully and restart with more memory");
      myGlobals.capturePackets = FLAG_NTOPSTATE_STOPCAP;
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
    traceEvent(CONST_TRACE_FATALERROR, 
	       "calloc(%d) @ %s:%d returned NULL [no more memory?]",
	       sz, file, line);
    if ( (myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) &&
         (myGlobals.disableStopcap != TRUE) ) {
      traceEvent(CONST_TRACE_WARNING, "ntop packet capture STOPPED");
      traceEvent(CONST_TRACE_INFO, "NOTE: ntop web server remains up");
      traceEvent(CONST_TRACE_INFO, "NOTE: Shutdown gracefully and restart with more memory");
      myGlobals.capturePackets = FLAG_NTOPSTATE_STOPCAP;
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
    traceEvent(CONST_TRACE_FATALERROR, 
	       "realloc(%d) @ %s:%d returned NULL [no more memory?]",
	       sz, file, line);
    if ( (myGlobals.capturePackets == FLAG_NTOPSTATE_RUN) &&
         (myGlobals.disableStopcap != TRUE) ) {
      traceEvent(CONST_TRACE_WARNING, "ntop packet capture STOPPED");
      traceEvent(CONST_TRACE_INFO, "NOTE: ntop web server remains up");
      traceEvent(CONST_TRACE_INFO, "NOTE: Shutdown gracefully and restart with more memory");
      myGlobals.capturePackets = FLAG_NTOPSTATE_STOPCAP;
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
#if (0)
   /* **********DIAGNOSTIC**********
      * Enable this code to look   *
      * for potential glibc 2.3.x  *
      * problems with free() in    *
      * fork()ed child             *
      ******************************
      if (myGlobals.childntoppid != 0) {
          traceEvent(CONST_TRACE_NOISY, "GLIBC23X: free in fork()ed child @ %s:%d", file, line);
          if (glib23xMessageWritten == 0) {
              traceEvent(CONST_TRACE_NOISY, "GLIBC23X: Please notify ntop-dev of NEW occurances");
              glib23xMessageWritten = 1;
          }
      }
      **********DIAGNOSTIC********** */
#endif
    free(*ptr);
    *ptr = NULL;
  }
}

/* ****************************************** */

#undef strdup /* just to be safe */
char* ntop_safestrdup(char *ptr, char* file, int line) {  
  if(ptr == NULL) {
    traceEvent(CONST_TRACE_WARNING, "strdup of NULL pointer @ %s:%d", file, line);
    return(strdup(""));
  } else {
    char* theOut;
    int len = strlen(ptr);
    
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

#endif /* MEMORY_DEBUG */
