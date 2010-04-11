/*
 *  Copyright (C) 2003 Luca Deri <deri@ntop.org>
 *                     Andreas Pfaller <apfaller@yahoo.com.au>
 *
 *                        http://www.ntop.org/
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

/* ************************************************************************* */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <getopt.h>
#include "p2clib.h"

/* Note: Setting DO_FREES to 0 skips free() calls for performance reasons.
   Since the program exits anyway after the run the leak does
   not really matter.
*/
#define DO_FREES 0

#define VERSION "2.0"

extern double log2(double);

typedef struct IPNode 
{
  struct IPNode *b[2];
  char cc[8];
  int  fnum;
} IPNode;

IPNode *Head;
int OptVerbose=0;
int OptReportDuplicateMappings=0;
int OptReportConflictingMappings=0;
int OptEmitConflictingMappings=0;
int OptOnlyTest=0;

/* ************************************************************************* */

int imaxblock(uint32_t ip, int prefix)
{
  while (prefix>0) {
    if ((ip & PREFIX2MASK(prefix-1)) != ip)
      break;
    prefix--;
  }
  return prefix;
}

/* ************************************************************************* */

void recursiveDump(FILE *fp, IPNode *p, uint32_t ip, int prefix)
{
  int i;
  static char ips[32];

  if (p->cc[0]!=0 && prefix!=0)
    fprintf(fp, "%s:%s/%d\n", p->cc, xntoa(ip, ips, sizeof(ips)), prefix);

  for (i=0; i<2; i++)
    if (p->b[i])
      recursiveDump(fp, p->b[i], ip | (i<<(31-prefix)), prefix+1);
}

/* ************************************************************************* */

void printInfo(char *msg, char *country, uint32_t ip, int prefix)
{
  char ips[32];

  fprintf(stderr, "%s: %3s:%s/%d\n", msg, country, xntoa(ip, ips, sizeof(ips)), prefix);
}

/* ************************************************************************* */


IPNode *consolidateTree(IPNode *p, char *country)
{
  int i;
  char *cc=country;

  if (strcmp(p->cc, country)==0)
    p->cc[0]=0;
    
  if (p->cc[0]!=0)
    cc=p->cc;

  for (i=0; i<2; i++)
    if (p->b[i])
      p->b[i]=consolidateTree(p->b[i], cc);

  if (p->b[0]==NULL && p->b[1]==NULL &&
      (p->cc[0]==0 || strcmp(country, p->cc)==0)) {
#if DO_FREES
    free(p);
#endif
    return NULL;
  }

  if (p->b[0]!=NULL && p->b[1]!=NULL &&
      p->b[0]->cc[0]!=0 && p->b[1]->cc[0]!=0 &&
      strcmp(p->b[0]->cc, p->b[1]->cc)==0) {
    strcpy(p->cc, p->b[0]->cc);
    for (i=0; i<2; i++) {
      p->b[i]->cc[0]=0;
      if (p->b[i]->b[0]==NULL && p->b[i]->b[1]==NULL) {
#if DO_FREES
        free(p->b[i]);
#endif
        p->b[i]=NULL;
      }
    }
  }

  return p;
}

/* ************************************************************************* */

void addNodeInternal(uint32_t ip, int prefix, char *country, int fnum)
{
  IPNode *p1=Head;
  IPNode *p2;
  int i, b;
  
  for (i=0; i<prefix; i++) {
    b=(ip>>(31-i)) & 0x1;
    if (!p1->b[b]) {
      if (!(p2=malloc(sizeof(IPNode))))
        exit(EXIT_FAILURE);
      memset(p2, 0, sizeof(IPNode));
      p1->b[b]=p2;
    }
    else
      p2=p1->b[b];
    
    p1=p2;
  }
  if (p2->cc[0]==0) {
    strcpy(p2->cc, country);
    p2->fnum=fnum;
  }
  else if (OptReportConflictingMappings || OptEmitConflictingMappings) {
   /* Note: the strstr test is a little too simple but works ok */
    if (strcmp(p2->cc, "LOC")!=0) {
      if (strstr(p2->cc, country)==NULL) { 
        if (OptReportConflictingMappings) {
          fprintf(stderr, "%2d-%2d %3s ", p2->fnum, fnum, p2->cc);
          printInfo("CONFLICT", country, ip, prefix);
        }

        if (OptEmitConflictingMappings) {
          i=strlen(p2->cc);
          if (strlen(p2->cc)+strlen(country)+1 < sizeof(p2->cc)) {
            strcat(p2->cc, "+");
            strcat(p2->cc, country);
          }
          else {
            fprintf(stderr, "%2d-%2d %s ", p2->fnum, fnum, p2->cc);
            printInfo("Too many conflicts", country, ip, prefix);
          }
        }
      }
      else if (OptReportDuplicateMappings) {
        fprintf(stderr, "%2d-%2d %3s ", p2->fnum, fnum, p2->cc);
        printInfo("DUPLICATE", country, ip, prefix);
      }
    }
  }
}

/* ************************************************************************* */

void addNode(uint32_t ip, int range, char *country, int fnum) 
{
  uint32_t ip1, ip2;
  int maxsize, maxdiff;

  if (range<1)
    return;

  if (!ip)
    return;

  ip1=ip;
  ip2=ip1+range-1;
  while (ip2>=ip1 && ip1!=0) {
    maxsize=imaxblock(ip1, 32);
    maxdiff=32 - (int) log2(ip2-ip1+1);
    if (maxsize<maxdiff)
      maxsize=maxdiff;

    addNodeInternal(ip1, maxsize, country, fnum);
    ip1 += 1 << (32-maxsize);
  }
}

/* ************************************************************************* */

void initIPCountryTable(int argc, char *argv[])
{
  int i;
  FILE *fin;
  
  if ((Head=malloc(sizeof(IPNode)))==NULL)
    exit(EXIT_FAILURE);
  strcpy(Head->cc, "***");
  Head->b[0]=NULL;
  Head->b[1]=NULL;  
  
  addNode(QUAD2IP(10,0,0,0), 256*256*256, "LOC", 0);
  addNode(QUAD2IP(127,0,0,0), 256*256*256, "LOC", 0);
  addNode(QUAD2IP(172,16,0,0), 16*256*256, "LOC", 0);
  addNode(QUAD2IP(192,168,0,0), 256*256, "LOC", 0);
 
  for (i=0; i<argc-optind; i++) {
    if ((fin=fopen(argv[i+optind], "r"))==NULL)
      continue;

    if (OptVerbose || OptReportConflictingMappings)
      fprintf(stderr, "== Reading File %d: %s\n", i, argv[i+optind]);
    
    while (!feof(fin)) {
      char buff[256];
      char *strtokState, *token, *cc, *ip, *range;

      if (fgets(buff, sizeof(buff), fin)==NULL)
        continue;
      if ((token=strtok_r(buff, "|", &strtokState))==NULL)
        continue;
      if ((cc=strtok_r(NULL, "|", &strtokState))==NULL)
        continue;
      if ((token=strtok_r(NULL, "|", &strtokState))==NULL)
        continue;
      if (strcmp(token, "ipv4"))
        continue;
      if ((ip=strtok_r(NULL, "|", &strtokState))==NULL)
        continue;
      if ((range=strtok_r(NULL, "|", &strtokState))==NULL)
        continue;

      strtoupper(cc);
      if (strcmp(cc, "GB")==0)
        cc="UK";

      addNode(xaton(ip), atoi(range), cc, i);
    }
    fclose(fin);
  }
}

/* ************************************************************************* */

void usage(void)
{
  fprintf(stderr, "prefixtablegen %s\n", VERSION);
  fprintf(stderr, "Usage: prefixtablegen [OPTION]... [FILE]...\n");
  fprintf(stderr, "Generate raw (p2c.raw.table) and optimized (p2c.opt.table)\n");
  fprintf(stderr, "IP prefix to country mapping files.\n\n");
  fprintf(stderr, "  -v   Print progress information\n");
  fprintf(stderr, "  -c   Print information about conflicting entries\n");
  fprintf(stderr, "  -C   Output all conflicting country names to mapping files\n");
  fprintf(stderr, "       WARNING: These files are not compatible with ntop\n");
  fprintf(stderr, "  -d   Print information about duplicate entries\n");
  fprintf(stderr, "  -t   Test only, dont write output file\n");
  exit(EXIT_FAILURE);
}

/* ************************************************************************* */

void parseOptions(int argc, char *argv[])
{
  int c;

  while ((c=getopt(argc, argv, "?cCdthv"))!=-1) {
    switch (c) {
      case 'c':
        OptReportConflictingMappings=1;
        break;
      case 'C':
        OptEmitConflictingMappings=1;
        break;
      case 'd':
        OptReportDuplicateMappings=1;
        break;
      case 't':
        OptOnlyTest=1;
        break;
      case 'v':
        OptVerbose++;
        break;
      case '?':
      case 'h':
      default:
      	usage();
        break;
    }
  }
}

/* ************************************************************************* */

int main(int argc, char *argv[]) 
{
  FILE *fp;

  parseOptions(argc, argv);
    
  initIPCountryTable(argc, argv);

  if (!OptOnlyTest) {
    if (OptVerbose)
      fprintf(stderr, "== Creating file p2c.raw.table ...\n");
    if ((fp=fopen("p2c.raw.table", "w"))==NULL)
      exit(EXIT_FAILURE);
    if (OptVerbose)
      fprintf(stderr, "== Writing file p2c.raw.table ...\n");
    recursiveDump(fp, Head, 0, 0);
    fclose(fp);
    
    if (OptVerbose)
      fprintf(stderr, "== Creating file p2c.opt.table ...\n");
    if ((fp=fopen("p2c.opt.table", "w"))==NULL)
      exit(EXIT_FAILURE);
    if (OptVerbose)
      fprintf(stderr, "== Optimizing table size ...\n");
    consolidateTree(Head, "");
    if (OptVerbose)
      fprintf(stderr, "== Writing file p2c.opt.table ...\n");
    recursiveDump(fp, Head, 0, 0);
    
    fclose(fp);
  }

  if (OptVerbose)
    fprintf(stderr, "== Done\n");

  exit(EXIT_SUCCESS);
}

