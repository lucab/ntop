#include <string.h>
#include <stdlib.h>

#ifndef _LEAKS_H_
#define _LEAKS_H_

extern void initLeaks();
extern void termLeaks();

extern void* myMalloc(size_t, int, char*);
extern void* myCalloc(size_t, size_t, int, char*);
extern void* myRealloc(void*, size_t, int, char*);
extern void  myFree(void*, int, char*);
extern char* myStrdup(char*, int, char*);
extern void  myRemoveXMPLeak(void*, int, char*);
extern void  myAddXMPLeak(void*, int, char*);

extern unsigned int PrintMemoryBlocks();
extern void ResetLeaks();

/*
#define malloc(a)     myMalloc((size_t)(a), __LINE__, __FILE__)
#define calloc(a, b)  myCalloc((size_t)(a), (size_t)(b), __LINE__, __FILE__)
#define realloc(a, b) myRealloc((void*)(a), (size_t)(b), __LINE__, __FILE__)
#define free(a)       myFree((void*)(a), __LINE__, __FILE__)
#define strdup(a)     myStrdup((char*)(a), __LINE__, __FILE__)
*/

#endif


