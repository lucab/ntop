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

/*
    Compile:

$ gcc -lm -o prefixtablegen prefixtablegen.c

 */

#define VERSION "1.0"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define QUAD2IP(a,b,c,d) ((a)<<24 | (b)<<16 | (c<<8) | (d))
#define PREFIX2MASK(n) (~0UL<<(32-(n)))

extern double log2(double);

typedef struct IPNode 
{
  struct IPNode *b[2];
  char cc[4];
} IPNode;

IPNode *Head;

int NodeCount=0;
int EntryCount=0;

char *strtolower(char *s) {
  while (*s) {
    *s=tolower(*s);
    s++;
  }
  
  return(s);
}


char *strtoupper(char *s) {
  while (*s) {
    *s=toupper(*s);
    s++;
  }
  
  return(s);
}


u_int32_t xaton(char *s)
{
  u_int32_t a, b, c, d;

  if (4!=sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d))
    return 0;
  return ((a&0xFF)<<24)|((b&0xFF)<<16)|((c&0xFF)<<8)|(d&0xFF);
}


char *xntoa(u_int32_t ip, char *result, int len)
{
  snprintf(result, len, "%d.%d.%d.%d",
           (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
  return result;
}

int range2prefix(u_int32_t range)
{
  static const u_int32_t rtable[]=
    {
      0x00000000,
      0x00000001, 0x00000003, 0x00000007, 0x0000000F,
      0x0000001F, 0x0000003F, 0x0000007F, 0x000000FF,
      0x000001FF, 0x000003FF, 0x000007FF, 0x00000FFF,
      0x00001FFF, 0x00003FFF, 0x00007FFF, 0x0000FFFF,
      0x0001FFFF, 0x0003FFFF, 0x0007FFFF, 0x000FFFFF,
      0x001FFFFF, 0x003FFFFF, 0x007FFFFF, 0x00FFFFFF,
      0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF,
      0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF
    };
  int i;

  for (i=32; i>=0; i--)
    if (range==rtable[i])
      return (32-i);

  return -1;
}


int imaxblock(u_int32_t ip, int prefix)
{
  while (prefix>0) {
    if ((ip & PREFIX2MASK(prefix-1)) != ip)
      break;
    prefix--;
  }
  return prefix;
}

void recursiveDump(FILE *fp, IPNode *p, u_int32_t ip, int prefix)
{
  int i;
  static char ips[32];

  if (p->cc[0]!=0 && prefix!=0)
    fprintf(fp, "%s:%s/%d\n", p->cc, xntoa(ip, ips, sizeof(ips)), prefix);

  for (i=0; i<2; i++)
    if (p->b[i])
      recursiveDump(fp, p->b[i], ip | (i<<(31-prefix)), prefix+1);
}

void printInfo(char *msg, char *country, u_int32_t ip, int prefix)
{
  char ips[32];

  fprintf(stderr, "%s: %3s-%s/%d\n", msg, country, xntoa(ip, ips, sizeof(ips)), prefix);
}

IPNode *consolidateTree(IPNode *p, char *country)
{
  int i;
  char *cc=country;

  if (strcmp(p->cc, country)==0)
  {
    p->cc[0]=0;
    EntryCount--;
  }
    
  if (p->cc[0]!=0)
    cc=p->cc;

  for (i=0; i<2; i++)
    if (p->b[i])
      p->b[i]=consolidateTree(p->b[i], cc);

  if (p->b[0]==NULL && p->b[1]==NULL &&
      (p->cc[0]==0 || strcmp(country, p->cc)==0)) {
    NodeCount--;
    if (p->cc[0]!=0)
      EntryCount--;
    free(p);
    return NULL;
  }

  if (p->b[0]!=NULL && p->b[1]!=NULL &&
      p->b[0]->cc[0]!=0 && p->b[1]->cc[0]!=0 &&
      strcmp(p->b[0]->cc, p->b[1]->cc)==0)
  {
    strcpy(p->cc, p->b[0]->cc);
    EntryCount-=2;
    for (i=0; i<2; i++) {
      p->b[i]->cc[0]=0;
      if (p->b[i]->b[0]==NULL && p->b[i]->b[1]==NULL)
      {
        NodeCount--;
        free(p->b[i]);
        p->b[i]=NULL;
      }
    }
  }

  return p;
}

  

void addNodeInternal(u_int32_t ip, int prefix, char *country)
{
  IPNode *p1=Head;
  IPNode *p2;
  int i, b;
  
  for (i=0; i<prefix; i++) {
    b=(ip>>(31-i)) & 0x1;
    if (!p1->b[b]) {
      if (!(p2=malloc(sizeof(IPNode))))
        exit(1);
      NodeCount++;
      memset(p2, 0, sizeof(IPNode));
      p1->b[b]=p2;
    }
    else
      p2=p1->b[b];
    
    p1=p2;
  }
  if (p2->cc[0]==0) {
    strcpy(p2->cc, country);
    EntryCount++;
  }
}


void addNode(u_int32_t ip, int range, char *country) 
{
//  char ips[32];
  u_int32_t ip1, ip2;
  int maxsize, maxdiff;

  if (range<1)
    return;

  if (!ip)
    return;

//  fprintf(stderr, "%s (%d) -> ", xntoa(ip, ips, sizeof(ips)), range);

  ip1=ip;
  ip2=ip1+range-1;
  while (ip2>=ip1 && ip1!=0) {
    maxsize=imaxblock(ip1, 32);
    maxdiff=32 - (int) log2(ip2-ip1+1);
    if (maxsize<maxdiff)
      maxsize=maxdiff;

//    fprintf(stderr, "%s/%d ", xntoa(ip1, ips, sizeof(ips)), maxsize);
    addNodeInternal(ip1, maxsize, country);
    ip1 += 1 << (32-maxsize);
  }
//  fprintf(stderr, "\n");
}

  
void initIPCountryTable(void)
{
  if ((Head=malloc(sizeof(IPNode)))==NULL)
    exit(1);
  strcpy(Head->cc, "***");
  Head->b[0]=NULL;
  Head->b[1]=NULL;  
  
  addNode(QUAD2IP(10,0,0,0), 256*256*256, "LOC");
  addNode(QUAD2IP(127,0,0,0), 256*256*256, "LOC");
  addNode(QUAD2IP(172,16,0,0), 16*256*256, "LOC");
  addNode(QUAD2IP(192,168,0,0), 256*256, "LOC");

  while (!feof(stdin)) {
    char buff[256];
    char *strtokState, *token, *cc, *ip, *range;

    if (fgets(buff, sizeof(buff), stdin)==NULL)
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

    addNode(xaton(ip), atoi(range), cc);
  }
}


int main(int argc, char *argv[]) 
{
  FILE *fp;
  int usage=0, quiet=1;

  if ( (argc >= 2) &&
       ( (strncasecmp("-h", argv[1], 2) == 0) ||
         (strncasecmp("--h", argv[1], 3) == 0) ) ) {
    usage=1;
  } else if ( (argc >= 2) &&
       ( (strncasecmp("-q", argv[1], 2) == 0) ||
         (strncasecmp("--q", argv[1], 3) == 0) ) ) {
    quiet=0;
  }

  if (usage) {
    printf("ntop (http://www.ntop.org) ip2cc prefixtablegen, version %s\n\n", VERSION);
    printf("Function: Generate raw and optimized p2c files, p2c.raw.table and p2c.opt.table\n\n");
    printf("Usage: cat *.data | ./prefixtablegen [-help] [-quiet]\n\n");
    exit(0);
  }

  if(quiet) printf("ntop (http://www.ntop.org) ip2cc prefixtablegen, version %s\n\n", VERSION);
 
  if(quiet) printf("  Initializing table (reading data)...\n\n");
  initIPCountryTable();

  if(quiet) printf("  Creating raw file...\n\n");
  if ((fp=fopen("p2c.raw.table", "w"))==NULL)
    exit(1);
  if(quiet) printf("  Dumping raw table...\n\n");
  recursiveDump(fp, Head, 0, 0);
  fclose(fp);
  
  if(quiet) printf("  Creating optimized file...\n\n");
  if ((fp=fopen("p2c.opt.table", "w"))==NULL)
    exit(1);
  if(quiet) printf("  Optimizing...\n\n");
  consolidateTree(Head, "");
  if(quiet) printf("  Dumping raw table...\n\n");
  recursiveDump(fp, Head, 0, 0);
  fclose(fp);

  if(quiet) printf("Done!\n\n");
  exit(0);
}

