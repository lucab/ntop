#include <string.h>
#include <stdlib.h>

#ifndef _LEAKS_H_
#define _LEAKS_H_

extern void initLeaks(void);
extern void termLeaks(void);

extern void* myMalloc(size_t, int, char*);
extern void* myCalloc(size_t, size_t, int, char*);
extern void* myRealloc(void*, size_t, int, char*);
extern void  myFree(void*, int, char*);
extern char* myStrdup(char*, int, char*);
extern void  myRemoveXMPLeak(void*, int, char*);
extern void  myAddXMPLeak(void*, int, char*);

extern unsigned int PrintMemoryBlocks(void);
extern void ResetLeaks(void);

#endif


