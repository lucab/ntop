/********************************************************************
Count-Min Sketches

G. Cormode 2003,2004

Updated: 2004-06 Added a floating point sketch and support for 
                 inner product point estimation
Initial version: 2003-12

This work is licensed under the Creative Commons
Attribution-NonCommercial License. To view a copy of this license,
visit http://creativecommons.org/licenses/by-nc/1.0/ or send a letter
to Creative Commons, 559 Nathan Abbott Way, Stanford, California
94305, USA. 
*********************************************************************/

#include <stdlib.h>
#include "countmin.h"

#define min(x,y)	((x) < (y) ? (x) : (y))
#define max(x,y)	((x) > (y) ? (x) : (y))

double eps;	               /* 1+epsilon = approximation factor */
double delta;                  /* probability of failure */

//int bits=32;

/************************************************************************/
/* Routines to support Count-Min sketches                               */
/************************************************************************/

CM_type * CM_Init(int width, int depth, int seed)
{     // Initialize the sketch based on user-supplied size
  CM_type * cm;
  int j;
  prng_type * prng;

  cm=(CM_type *) malloc(sizeof(CM_type));
  prng=prng_Init(-abs(seed),2); 
  // initialize the generator to pick the hash functions

  if (cm && prng)
    {
      cm->depth=depth;
      cm->width=width;
      cm->count=0;
      cm->prng = prng; /* L. Deri */
      cm->counts=(int **)calloc(sizeof(int *),cm->depth);
      cm->counts[0]=(int *)calloc(sizeof(int), cm->depth*cm->width);
      cm->hasha=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      cm->hashb=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      if (cm->counts && cm->hasha && cm->hashb && cm->counts[0])
	{
	  for (j=0;j<depth;j++)
	    {
	      cm->hasha[j]=prng_int(prng) & MOD;
	      cm->hashb[j]=prng_int(prng) & MOD;
	      // pick the hash functions
	      cm->counts[j]=(int *) cm->counts[0]+(j*cm->width);
	    }
	}
      else cm=NULL;
    }
  return cm;
}

CM_type * CM_Copy(CM_type * cmold)
{     // create a new sketch with the same parameters as an existing one
  CM_type * cm;
  int j;

  if (!cmold) return(NULL);
  cm=(CM_type *) malloc(sizeof(CM_type));
  if (cm)
    {
      cm->depth=cmold->depth;
      cm->width=cmold->width;
      cm->count=0;
      cm->counts=(int **)calloc(sizeof(int *),cm->depth);
      cm->counts[0]=(int *)calloc(sizeof(int), cm->depth*cm->width);
      cm->hasha=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      cm->hashb=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      if (cm->counts && cm->hasha && cm->hashb && cm->counts[0])
	{
	  for (j=0;j<cm->depth;j++)
	    {
	      cm->hasha[j]=cmold->hasha[j];
	      cm->hashb[j]=cmold->hashb[j];
	      cm->counts[j]=(int *) cm->counts[0]+(j*cm->width);
	    }
	}
      else cm=NULL;
    }
  return cm;
}

void CM_Destroy(CM_type * cm)
{     // get rid of a sketch and free up the space
  if (!cm) return;
  if (cm->counts)
    {
      if (cm->counts[0]) free(cm->counts[0]);
      free(cm->counts);
      cm->counts=NULL;
    }
  if (cm->hasha) free(cm->hasha); cm->hasha=NULL;
  if (cm->hashb) free(cm->hashb); cm->hashb=NULL;
  prng_Destroy(cm->prng); /* L.Deri */
  free(cm);  cm=NULL;
}

int CM_Size(CM_type * cm)
{ // return the size of the sketch in bytes
  int counts, hashes, admin;
  if (!cm) return 0;
  admin=sizeof(CM_type);
  counts=cm->width*cm->depth*sizeof(int);
  hashes=cm->depth*2*sizeof(unsigned int);
  return(admin + hashes + counts);
}

void CM_Update(CM_type * cm, unsigned int item, int diff)
{
  int j;

  if (!cm) return;
  cm->count+=diff;
  for (j=0;j<cm->depth;j++)
    cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],item) % cm->width]+=diff;
  // this can be done more efficiently if the width is a power of two
}

int CM_PointEst(CM_type * cm, unsigned int query)
{
  // return an estimate of the count of an item by taking the minimum
  int j, ans;

  if (!cm) return 0;
  ans=cm->counts[0][hash31(cm->hasha[0],cm->hashb[0],query) % cm->width];
  for (j=1;j<cm->depth;j++)
    ans=min(ans,cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],query)%cm->width]);
  // this can be done more efficiently if the width is a power of two
  return (ans);
}

#if 0
int CM_PointMed(CM_type * cm, unsigned int query)
{
  // return an estimate of the count by taking the median estimate
  // useful when counts can become negative
  // depth needs to be larger for this to work well
  int j, * ans, result=0;

  if (!cm) return 0;
  ans=(int *) calloc(1+cm->depth,sizeof(int));
  for (j=0;j<cm->depth;j++)
    ans[j+1]=cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],query)%cm->width];

  if (cm->depth==1)
    result=ans[1];
  else
    if (cm->depth==2)
      {
	//result=(ans[1]+ans[2])/2;
	if (abs(ans[1]) < abs(ans[2]))
	  result=ans[1]; else result=ans[2];
	// special tweak for small depth sketches
      }
    else
      result=(MedSelect(1+cm->depth/2,cm->depth,ans));
  return result;
  // need to adjust for routine starting at 1
}
#endif

int CM_Compatible(CM_type * cm1, CM_type * cm2)
{ // test whether two sketches are comparable (have same parameters)
  int i;
  if (!cm1 || !cm2) return 0;
  if (cm1->width!=cm2->width) return 0;
  if (cm1->depth!=cm2->depth) return 0;
  for (i=0;i<cm1->depth;i++)
    {
      if (cm1->hasha[i]!=cm2->hasha[i]) return 0;
      if (cm1->hashb[i]!=cm2->hashb[i]) return 0;
    }
  return 1;
}

int CM_InnerProd(CM_type * cm1, CM_type * cm2)
{ // Estimate the inner product of two vectors by comparing their sketches
  int i,j, tmp, result;

  result=0;
  if (CM_Compatible(cm1,cm2))
    {
      for (i=0;i<cm1->width;i++)
	result+=cm1->counts[0][i]*cm2->counts[0][i];
      for (j=1;j<cm1->depth;j++)
	{
	  tmp=0;
	  for (i=0;i<cm1->width;i++)
	    tmp+=cm1->counts[j][i]*cm2->counts[j][i];
	  result=min(tmp,result);
	}
    }
  return result;
}

int CM_Residue(CM_type * cm, unsigned int * Q)
{
// CM_Residue computes the sum of everything left after the points 
// from Q have been removed
// Q is a list of points, where Q[0] gives the length of the list

  char * bitmap;
  int i,j;
  int estimate=0, nextest;

  if (!cm) return 0;
  bitmap=(char *) calloc(cm->width,sizeof(char));
  for (j=0;j<cm->depth;j++)
    {
      nextest=0;
      for (i=0;i<cm->width;i++)
	bitmap[i]=0;
      for (i=1;i<Q[0];i++)
	bitmap[hash31(cm->hasha[j],cm->hashb[j],Q[i]) % cm->width]=1;
      for (i=0;i<cm->width;i++)
	if (bitmap[i]==0) nextest+=cm->counts[j][i];
      estimate=max(estimate,nextest);
    }
  return(estimate);
}

/************************************************************************/
/* Routines to support Count-Min sketches with floating point data      */
/************************************************************************/

CMF_type * CMF_Init(int width, int depth, int seed)
{     // Initialize the sketch based on user-supplied size
  CMF_type * cm;
  int j;
  prng_type * prng;

  cm=(CMF_type *) malloc(sizeof(CMF_type));

  prng=prng_Init(-abs(seed),2); 
  // initialize the generator to pick the hash functions

  if (cm && prng)
    {
      cm->depth=depth;
      cm->width=width;
      cm->count=0;
      cm->counts=(double **)calloc(sizeof(double *),cm->depth);
      cm->counts[0]=(double *)calloc(sizeof(double), cm->depth*cm->width);
      cm->hasha=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      cm->hashb=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      if (cm->counts && cm->hasha && cm->hashb && cm->counts[0])
	{
	  for (j=0;j<depth;j++)
	    {
	      cm->hasha[j]=prng_int(prng) & MOD;
	      cm->hashb[j]=prng_int(prng) & MOD;
	      // pick the hash functions
	      cm->counts[j]=(double *) cm->counts[0]+(j*cm->width);
	    }
	}
      else cm=NULL;
    }
  return cm;
}

CMF_type * CMF_Copy(CMF_type * cmold)
{     // create a new sketch with the same parameters as an existing one
  CMF_type * cm;
  int j;

  if (!cmold) return(NULL);
  cm=(CMF_type *) malloc(sizeof(CMF_type));
  if (cm)
    {
      cm->depth=cmold->depth;
      cm->width=cmold->width;
      cm->count=0;
      cm->counts=(double **)calloc(sizeof(double *),cm->depth);
      cm->counts[0]=(double *)calloc(sizeof(double), cm->depth*cm->width);
      cm->hasha=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      cm->hashb=(unsigned int *)calloc(sizeof(unsigned int),cm->depth);
      if (cm->counts && cm->hasha && cm->hashb && cm->counts[0])
	{
	  for (j=0;j<cm->depth;j++)
	    {
	      cm->hasha[j]=cmold->hasha[j];
	      cm->hashb[j]=cmold->hashb[j];
	      cm->counts[j]=(double *) cm->counts[0]+(j*cm->width);
	    }
	}
      else cm=NULL;
    }
  return cm;
}

void CMF_Destroy(CMF_type * cm)
{     // get rid of a sketch and free up the space
  if (!cm) return;
  if (cm->counts)
    {
      if (cm->counts[0]) free(cm->counts[0]);
      free(cm->counts);
      cm->counts=NULL;
    }

  
  if (cm->hasha) free(cm->hasha); cm->hasha=NULL;
  if (cm->hashb) free(cm->hashb); cm->hashb=NULL;
  free(cm);  cm=NULL;
}

int CMF_Size(CMF_type * cm)
{ // return the size of the sketch in bytes
  int counts, hashes, admin;
  if (!cm) return 0;
  admin=sizeof(CM_type);
  counts=cm->width*cm->depth*sizeof(double);
  hashes=cm->depth*2*sizeof(unsigned int);
  return(admin + hashes + counts);
}

void CMF_Update(CMF_type * cm, unsigned int item, double diff)
{
  int j;

  if (!cm) return;
  cm->count+=diff;
  for (j=0;j<cm->depth;j++)
    cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],item) % cm->width]+=diff;
  // this can be done more efficiently if the width is a power of two
}

int CMF_PointEst(CMF_type * cm, unsigned int query)
{
  // return an estimate of the count of an item by taking the minimum
  int j, ans;

  if (!cm) return 0;
  ans=cm->counts[0][hash31(cm->hasha[0],cm->hashb[0],query) % cm->width];
  for (j=1;j<cm->depth;j++)
    ans=min(ans,cm->counts[j][hash31(cm->hasha[j],cm->hashb[j],query)%cm->width]);
  // this can be done more efficiently if the width is a power of two
  return (ans);
}

int CMF_Compatible(CMF_type * cm1, CMF_type * cm2)
{ // test whether two sketches are comparable (have same parameters)
  int i;
  if (!cm1 || !cm2) return 0;
  if (cm1->width!=cm2->width) return 0;
  if (cm1->depth!=cm2->depth) return 0;
  for (i=0;i<cm1->depth;i++)
    {
      if (cm1->hasha[i]!=cm2->hasha[i]) return 0;
      if (cm1->hashb[i]!=cm2->hashb[i]) return 0;
    }
  return 1;
}

double CMF_PointProd(CMF_type * cm1, CMF_type * cm2, unsigned int query)
{ // Estimate the inner product of two vectors by comparing their sketches
  int j, loc;
  double tmp, ans;

  ans=0.0;
  if (CMF_Compatible(cm1,cm2))
    {
      loc=hash31(cm1->hasha[0],cm1->hashb[0],query) % cm1->width;
      ans=cm1->counts[0][loc]*cm2->counts[0][loc];
      for (j=1;j<cm1->depth;j++)
	{
	  loc=hash31(cm1->hasha[j],cm1->hashb[j],query) % cm1->width;
	  tmp=cm1->counts[j][loc]*cm2->counts[j][loc];
	  ans=min(ans,tmp); 
	}
    }
  return (ans);
}
 
double CMF_InnerProd(CMF_type * cm1, CMF_type * cm2)
{ // Estimate the inner product of two vectors by comparing their sketches
  int i,j;
  double tmp, result;

  result=0;
  if (CMF_Compatible(cm1,cm2))
    {
      for (i=0;i<cm1->width;i++)
	result+=cm1->counts[0][i]*cm2->counts[0][i];
      for (j=1;j<cm1->depth;j++)
	{
	  tmp=0.0;
	  for (i=0;i<cm1->width;i++)
	    tmp+=cm1->counts[j][i]*cm2->counts[j][i];
	  result=min(tmp,result);
	}
    }
  return result;
}

/************************************************************************/
/* Routines to support hierarchical Count-Min sketches                  */
/************************************************************************/

CMH_type * CMH_Init(int width, int depth, int U, int gran)
{
  // initialize a hierarchical set of sketches for range queries 
  // heavy hitters or quantiles

  CMH_type * cmh;
  int i,j,k;
  prng_type * prng;

  if (U<=0 || U>32) return(NULL);
  // U is the log the size of the universe in bits

  if (gran>U || gran<1) return(NULL);
  // gran is the granularity to look at the universe in 
  // check that the parameters make sense...

  cmh=(CMH_type *) malloc(sizeof(CMH_type));

  prng=prng_Init(-12784,2);
  // initialize the generator for picking the hash functions

  if (cmh && prng)
    {
      cmh->depth=depth;
      cmh->width=width;
      cmh->count=0;
      cmh->U=U;
      cmh->gran=gran;
      cmh->levels=(int) ceil(((float) U)/((float) gran));
      for (j=0;j<cmh->levels;j++)
	if (1<<(cmh->gran*j) <= cmh->depth*cmh->width)
	  cmh->freelim=j;
      //find the level up to which it is cheaper to keep exact counts
      cmh->freelim=cmh->levels-cmh->freelim;
      
      cmh->counts=(int **) calloc(sizeof(int *), 1+cmh->levels);
      cmh->hasha=(unsigned int **)calloc(sizeof(unsigned int *),1+cmh->levels);
      cmh->hashb=(unsigned int **)calloc(sizeof(unsigned int *),1+cmh->levels);
      j=1;
      for (i=cmh->levels-1;i>=0;i--)
	{
	  if (i>=cmh->freelim)
	    { // allocate space for representing things exactly at high levels
	      cmh->counts[i]=calloc(1<<(cmh->gran*j),sizeof(int));
	      j++;
	      cmh->hasha[i]=NULL;
	      cmh->hashb[i]=NULL;
	    }
	  else 
	    { // allocate space for a sketch
	      cmh->counts[i]=(int *)calloc(sizeof(int), cmh->depth*cmh->width);
	      cmh->hasha[i]=(unsigned int *)
		calloc(sizeof(unsigned int),cmh->depth);
	      cmh->hashb[i]=(unsigned int *)
		calloc(sizeof(unsigned int),cmh->depth);

	      if (cmh->hasha[i] && cmh->hashb[i])
		for (k=0;k<cmh->depth;k++)
		  { // pick the hash functions
		    cmh->hasha[i][k]=prng_int(prng) & MOD;
		    cmh->hashb[i][k]=prng_int(prng) & MOD;
		  }
	    }
	}
    }
  return cmh;
}

void CMH_Destroy(CMH_type * cmh)
{  // free up the space 
  int i;
  if (!cmh) return;
  for (i=0;i<cmh->levels;i++)
    {
      if (i>=cmh->freelim)
	{
	  free(cmh->counts[i]);
	}
      else 
	{
	  free(cmh->hasha[i]);
	  free(cmh->hashb[i]);
	  free(cmh->counts[i]);
	}
    }
  free(cmh->counts);
  free(cmh->hasha);
  free(cmh->hashb);
  free(cmh);
  cmh=NULL;
}

void CMH_Update(CMH_type * cmh, unsigned int item, int diff)
{ // update with a new value
  int i,j,offset;

  if (!cmh) return;
  cmh->count+=diff;
  for (i=0;i<cmh->levels;i++)
    {
      offset=0;
      if (i>=cmh->freelim)
	{
	  cmh->counts[i][item]+=diff;
	  // keep exact counts at high levels in the hierarchy  
	}
      else
	for (j=0;j<cmh->depth;j++)
	  {
	    cmh->counts[i][(hash31(cmh->hasha[i][j],cmh->hashb[i][j],item) 
			    % cmh->width) + offset]+=diff;
	    // this can be done more efficiently if the width is a power of two
	    offset+=cmh->width;
	  }
      item>>=cmh->gran;
    }
}

int CMH_Size(CMH_type * cmh)
{ // return the size used in bytes
  int counts, hashes, admin,i;
  if (!cmh) return 0;
  admin=sizeof(CMH_type);
  counts=cmh->levels*sizeof(int **);
  for (i=0;i<cmh->levels;i++)
    if (i>=cmh->freelim)
      counts+=(1<<(cmh->gran*(cmh->levels-i)))*sizeof(int);
    else
      counts+=cmh->width*cmh->depth*sizeof(int);
  hashes=(cmh->levels-cmh->freelim)*cmh->depth*2*sizeof(unsigned int);
  hashes+=(cmh->levels)*sizeof(unsigned int *);
  return(admin + hashes + counts);
}

int CMH_count(CMH_type * cmh, int depth, int item)
{
  // return an estimate of item at level depth

  int j;
  int offset;
  int estimate;

  if (depth>=cmh->levels) return(cmh->count);
  if (depth>=cmh->freelim)
    { // use an exact count if there is one
      return(cmh->counts[depth][item]);
    }
  // else, use the appropriate sketch to make an estimate
  offset=0;
  estimate=cmh->counts[depth][(hash31(cmh->hasha[depth][0],
				      cmh->hashb[depth][0],item) 
			       % cmh->width) + offset];
  for (j=1;j<cmh->depth;j++)
    {
      offset+=cmh->width;
      estimate=min(estimate,
		   cmh->counts[depth][(hash31(cmh->hasha[depth][j],
					      cmh->hashb[depth][j],item) 
				       % cmh->width) + offset]);
    }
  return(estimate);
}

void CMH_recursive(CMH_type * cmh, int depth, int start, 
		    int thresh, unsigned int * results)
{
  // for finding heavy hitters, recursively descend looking 
  // for ranges that exceed the threshold

  int i;
  int blocksize;
  int estcount;
  int itemshift;

  estcount=CMH_count(cmh,depth,start);
  if (estcount>=thresh) 
    { 
      if (depth==0)
	{
	  if (results[0]<cmh->width)
	    {
	      results[0]++;
	      results[results[0]]=start;
	    }
	}
      else
	{
	  blocksize=1<<cmh->gran;
	  itemshift=start<<cmh->gran;
	  // assumes that gran is an exact multiple of the bit dept
	  for (i=0;i<blocksize;i++)
	    CMH_recursive(cmh,depth-1,itemshift+i,thresh,results);
	}
    }
}

int * CMH_FindHH(CMH_type * cmh, int thresh)
{ // find all items whose estimated count is greater than phi n

  unsigned int * results;
  results=(unsigned int *) calloc(cmh->width,sizeof(unsigned int));
  results[0]=0;

  CMH_recursive(cmh,cmh->levels,0,thresh,results);
  return(results);
}

int CMH_Rangesum(CMH_type * cmh, int start, int end)
{
  // compute a range sum: 
  // start at bottom level
  // compute any estimates needed at each level
  // work upwards

  int leftend,rightend,i,depth, result, topend;

  topend=1<<cmh->U;
  end=min(topend,end);
  if ((end>topend) && (start==0))
    return cmh->count;

  end+=1; // adjust for end effects
  result=0;
  for (depth=0;depth<=cmh->levels;depth++)
    {
      if (start==end) break;
      if ((end-start+1)<(1<<cmh->gran))
	{ // at the highest level, avoid overcounting	
	  for (i=start;i<end;i++)
	    result+=CMH_count(cmh,depth,i);
	  break;
	}
      else
	{  // figure out what needs to be done at each end
	  leftend=(((start>>cmh->gran)+1)<<cmh->gran) - start;
	  rightend=(end)-((end>>cmh->gran)<<cmh->gran);
	  if ((leftend>0) && (start<end))
	    for (i=0;i<leftend;i++)
	      {
		result+=CMH_count(cmh,depth,start+i);
	      }
	  if ((rightend>0) && (start<end))
	    for (i=0;i<rightend;i++)
	      {
		result+=CMH_count(cmh,depth,end-i-1);
	      }
	  start=start>>cmh->gran;
	  if (leftend>0) start++;
	  end=end>>cmh->gran;
	}
    }
  return result;
}

int CMH_FindRange(CMH_type * cmh, int sum)
{
  unsigned long low, high, mid=0, est;
  int i;
  // find a range starting from zero that adds up to sum

  if (cmh->count<sum) return 1<<(cmh->U);
  low=0;
  high=1<<cmh->U;
  for (i=0;i<cmh->U;i++)
    {
      mid=(low+high)/2;
      est=CMH_Rangesum(cmh,0,mid);
      if (est>sum)
	high=mid;
      else
	low=mid;
    }
  return mid;

}

int CMH_AltFindRange(CMH_type * cmh, int sum)
{
  unsigned long low, high, mid=0, est, top;
  int i;
  // find a range starting from the right hand side that adds up to sum

  if (cmh->count<sum) return 1<<(cmh->U);
  low=0;
  top=1<<cmh->U;
  high=top;
  for (i=0;i<cmh->U;i++)
    {
      mid=(low+high)/2;
      est=CMH_Rangesum(cmh,mid,top);
      if (est<sum)
	high=mid;
      else
	low=mid;
    }
  return mid;

}

int CMH_Quantile(CMH_type * cmh, float frac)
{
  // find a quantile by doing the appropriate range search
  if (frac<0) return 0;
  if (frac>1) 
    return 1<<cmh->U;
  return ((CMH_FindRange(cmh,cmh->count*frac)+
	   CMH_AltFindRange(cmh,cmh->count*(1-frac)))/2);
  // each result gives a lower/upper bound on the location of the quantile
  // with high probability, these will be close: only a small number of values
  // will be between the estimates. 
}

long long CMH_F2Est(CMH_type * cmh)
{
  // A heuristic for estimating the F2 of a stream
  // tends to overestimate a great deal on non-skewed streams

  int i,j,k;
  long long est, result;

  k=0; result=-1;
  for (i=0;i<cmh->depth;i++)
    {
      est=0;
      for (j=0;j<cmh->width;j++)
	{
	  est+=(long long) cmh->counts[0][k] * (long long) cmh->counts[0][k];
	  k++;
	}
      if (result<0) result=est; else
	result=min(result,est);
    }
  return result;
}
