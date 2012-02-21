// Two different structures: 
//   1 -- The basic CM Sketch
//   2 -- The hierarchical CM Sketch: with log n levels, for range sums etc. 

#ifndef min
#define min(x,y)	((x) < (y) ? (x) : (y))
#endif

#ifndef max
#define max(x,y)	((x) > (y) ? (x) : (y))
#endif

#include "prng.h"

typedef struct CM_type{
  long long count;
  int depth;
  int width;
  int ** counts;
  unsigned int *hasha, *hashb;
  prng_type * prng; /* L. Deri */
} CM_type;

typedef struct CMF_type{ // shadow of above stucture with floats
  double count;
  int depth;
  int width;
  double ** counts;
  unsigned int *hasha, *hashb;
} CMF_type;

extern CM_type * CM_Init(int, int, int);
extern CM_type * CM_Copy(CM_type *);
extern void CM_Destroy(CM_type *);
extern int CM_Size(CM_type *);

extern void CM_Update(CM_type *, unsigned int, int); 
extern int CM_PointEst(CM_type *, unsigned int);
extern int CM_PointMed(CM_type *, unsigned int);
extern int CM_InnerProd(CM_type *, CM_type *);
extern int CM_Residue(CM_type *, unsigned int *);

extern CMF_type * CMF_Init(int, int, int);
extern CMF_type * CMF_Copy(CMF_type *);
extern void CMF_Destroy(CMF_type *);
extern int CMF_Size(CMF_type *);
extern void CMF_Update(CMF_type *, unsigned int, double); 
extern double CMF_InnerProd(CMF_type *, CMF_type *);
extern double CMF_PointProd(CMF_type *, CMF_type *, unsigned int);

typedef struct CMH_type{
  long long count;
  int U; // size of the universe in bits
  int gran; // granularity: eg 1, 4 or 8 bits
  int levels; // function of U and gran
  int freelim; // up to which level to keep exact counts
  int depth;
  int width;
  int ** counts;
  unsigned int **hasha, * *hashb;
} CMH_type;

extern CMH_type * CMH_Init(int, int, int, int);
extern CMH_type * CMH_Copy(CMH_type *);
extern void CMH_Destroy(CMH_type *);
extern int CMH_Size(CMH_type *);

extern void CMH_Update(CMH_type *, unsigned int, int);
extern int * CMH_FindHH(CMH_type *, int);
extern int CMH_Rangesum(CMH_type *, int, int);

extern int CMH_FindRange(CMH_type * cmh, int);
extern int CMH_Quantile(CMH_type *cmh,float);
extern long long CMH_F2Est(CMH_type *);
