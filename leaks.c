#include "ntop.h"


#ifdef MEMORY_DEBUG 

#include <stdio.h>
#include <stdlib.h>

#undef malloc
#undef free
#undef strdup

typedef struct memoryBlock {
  void*               memoryLocation;   /* Malloc address              */
  size_t              blockSize;        /* Block size                  */
  char*               programLocation;  /* Program address: file, line */
  struct memoryBlock* nextBlock;        /* Next memory block           */
  short alreadyTraced;
} MemoryBlock;

static MemoryBlock *theRoot = NULL;
static char tmpStr[255];

#ifdef MULTITHREADED
static pthread_mutex_t leaksMutex;
#endif

unsigned int PrintMemoryBlocks(); /* Forward declaration */

/* *************************************** */

void* myMalloc(size_t theSize, int theLine, char* theFile) {
  MemoryBlock *tmpBlock;

#if defined(MULTITHREADED)
  accessMutex(&leaksMutex, "myMalloc");
#endif

  tmpBlock = (MemoryBlock*)malloc(sizeof(MemoryBlock));

  if(tmpBlock == NULL) {
    traceEvent(TRACE_WARNING, "Malloc error (not enough memory): %s, %d\n", 
	    theFile, theLine);

#if defined(MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif
    return(NULL);
  }
  
  tmpBlock->blockSize = theSize;
  tmpBlock->memoryLocation = malloc(theSize);
  tmpBlock->alreadyTraced = 0;

  allocatedMemory += theSize;

  if(tmpBlock->memoryLocation == NULL) {
    traceEvent(TRACE_WARNING, "Malloc error (not enough memory): %s, %d (size = %d)\n", 
	    theFile, theLine, (int)theSize);
#if defined(MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif
    return(NULL);
  }

  snprintf(tmpStr, sizeof(tmpStr), "file %s, line %d.", theFile, theLine);
  tmpBlock->programLocation = strdup(tmpStr);
  tmpBlock->nextBlock = theRoot;
  theRoot = tmpBlock;

#if defined(MULTITHREADED)
  releaseMutex(&leaksMutex);
#endif

  return(tmpBlock->memoryLocation);
}

/* *************************************** */

void* myCalloc(size_t numObj, size_t theSize, int theLine, char* theFile) {
  int numElems = numObj*theSize;
  void* thePtr = myMalloc(numElems, theLine, theFile);

  if(thePtr != NULL)
    memset(thePtr, '\0', numElems);

  return(thePtr);
}

/* *************************************** */

void* myRealloc(void* thePtr, size_t theSize, int theLine, char* theFile) {
  MemoryBlock *theScan, *lastPtr, *theNewPtr;
  
#if defined(MULTITHREADED)
  accessMutex(&leaksMutex, "myRealloc");
#endif

  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEvent(TRACE_WARNING, "Realloc error (Ptr %p NOT allocated): %s, %d\n", 
	    thePtr, theFile, theLine);
#if defined(MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif
    return(NULL);
  } else {    
    theNewPtr = myMalloc(theSize, theLine, theFile);
      
    if(theSize > theScan->blockSize)
      memcpy(theNewPtr, thePtr, theScan->blockSize);
    else
      memcpy(theNewPtr, thePtr, theSize);
	
    free(theScan->memoryLocation);
    free(theScan->programLocation);
      
    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);     

#if defined(MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif

    return(theNewPtr);
  }
}

/* *************************************** */

void myFree(void* thePtr, int theLine, char* theFile) {
  MemoryBlock *theScan, *lastPtr;
  
#if defined(MULTITHREADED)
  accessMutex(&leaksMutex, "myFree");
#endif

  theScan = theRoot;
 
  while((theScan != NULL) && (theScan->memoryLocation != thePtr)) {
    lastPtr = theScan;
    theScan = theScan->nextBlock;
  }

  if(theScan == NULL) {
    traceEvent(TRACE_WARNING, "Free error (Ptr %p NOT allocated): %s, %d\n", 
	    thePtr, theFile, theLine);
#if defined(MULTITHREADED)
    releaseMutex(&leaksMutex);
#endif
    return;
  } else {
    allocatedMemory -= theScan->blockSize;

    free(theScan->memoryLocation);
    free(theScan->programLocation);

    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);
  }

#if defined(MULTITHREADED)
  releaseMutex(&leaksMutex);
#endif
}

/* *************************************** */

char* myStrdup(char* theStr, int theLine, char* theFile) {
  char* theOut;
  int len = strlen(theStr);
  
  theOut = (char*)myMalloc((len+1), theLine, theFile);
  strncpy(theOut, theStr, len);

  return(theOut);
}

/* *************************************** */

void ResetLeaks(void) {
  MemoryBlock *theScan;

  theScan = theRoot;
 
  while(theScan != NULL) {
    theScan->alreadyTraced = 1;
    theScan = theScan->nextBlock;
  }

  allocatedMemory = 0; /* Reset counter */
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
      traceEvent(TRACE_INFO,"Block %5d (addr %p, size %4d): %s\n", i++, 
	      theScan->memoryLocation, theScan->blockSize, theScan->programLocation);
      totMem += theScan->blockSize;
    }

    theScan->alreadyTraced = 1;
    tmp = theScan->memoryLocation;
    theScan = theScan->nextBlock;
  }

  traceEvent(TRACE_INFO,"\nTotal allocated memory: %u bytes\n\n", totMem);

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
    traceEvent(TRACE_WARNING, "GimmePointerSize error: Ptr %p NOT allocated\n", thePtr);
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
    traceEvent(TRACE_WARNING, "GimmePointerInfo error: Ptr %p NOT allocated\n", thePtr);
    return -1;
  } else {      
    traceEvent(TRACE_WARNING, "Block (addr %p, size %d): %s\n", theScan->memoryLocation, 
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
    traceEvent(TRACE_WARNING, "Malloc error (not enough memory): %s, %d\n", 
	    theFile, theLine);
    return;
  }
  
  tmpBlock->blockSize = 0;
  tmpBlock->memoryLocation = thePtr;
  snprintf(tmpStr, sizeof(tmpStr), "file %s, line %d.", theFile, theLine);
  tmpBlock->programLocation = strdup(tmpStr);
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
    traceEvent(TRACE_WARNING, "Free  block error (Ptr %p NOT allocated): %s, %d\n", 
	       thePtr, theFile, theLine);
    return;
  } else {
    free(theScan->programLocation);
    
    if(theScan == theRoot)
      theRoot = theRoot->nextBlock;
    else
      lastPtr->nextBlock = theScan->nextBlock;

    free(theScan);
  }
}

/* *************************************** */

void initLeaks(void) {
#ifdef MULTITHREADED
  createMutex(&leaksMutex);
#endif
}

/* *************************************** */

void termLeaks(void) {
  PrintMemoryBlocks();
#ifdef MULTITHREADED
  deleteMutex(&leaksMutex);
#endif
}

/* ************************************ */

void* ntop_malloc(unsigned int sz, char* file, int line) {
#ifdef MEMORY_DEBUG
  traceEvent(file, line, "malloc(%d) [%s]", 
	     sz, formatBytes(allocatedMemory, 0));
#endif

  return(myMalloc(sz, line, file));
}

/* ************************************ */

char* ntop_strdup(char *str, char* file, int line) {
#ifdef MEMORY_DEBUG
  traceEvent(file, line, "strdup(%s) [%s]", str, 
	     formatBytes(allocatedMemory, 0));
#endif

  return(myStrdup(str, line, file));
}

/* ************************************ */

void ntop_free(void *ptr, char* file, int line) {
#ifdef MEMORY_DEBUG
  traceEvent(file, line, "free(%x) [%s]", ptr, 
	     formatBytes(allocatedMemory, 0));
#endif

  return(myFree(ptr, line, file));
}

#endif /* MEMORY_DEBUG */
