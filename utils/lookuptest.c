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

#define VERSION "2.0"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include "p2clib.h"

typedef struct IPNode 
{
  struct IPNode *b[2];
  char cc[8];
} IPNode;

IPNode *Head;

char *OptTableFilename="./p2c.opt.table";

/* ************************************************************************* */

void addNodeInternal(uint32_t ip, int prefix, char *country)
{
  IPNode *p1=Head;
  IPNode *p2;
  int i, b;
  
  for (i=0; i<prefix; i++) {
    b=(ip>>(31-i)) & 0x1;
    if (!p1->b[b]) {
      if (!(p2=malloc(sizeof(IPNode))))
        exit(1);
      memset(p2, 0, sizeof(IPNode));
      p1->b[b]=p2;
    }
    else
      p2=p1->b[b];
    
    p1=p2;
  }
  if (p2->cc[0]==0) {
    strncpy(p2->cc, country, sizeof(p2->cc));
    p2->cc[sizeof(p2->cc)-1]=0;
  }
}

/* ************************************************************************* */

void initIPCountryTable(void)
{
  FILE *fd;
  
  if ((Head=malloc(sizeof(IPNode)))==NULL)
    exit(1);
  strcpy(Head->cc, "***");
  Head->b[0]=NULL;
  Head->b[1]=NULL;  

  fd = fopen(OptTableFilename, "r");
  if (fd==NULL) {
    perror(OptTableFilename);
    exit(EXIT_FAILURE);
  }

  while (!feof(fd)) {
    char buff[256];
    char *strtokState, *cc, *ip, *prefix;
      
    if (fgets(buff, sizeof(buff), fd)==NULL)
      continue;
    if ((cc=strtok_r(buff, ":", &strtokState))==NULL)
      continue;
    if ((ip=strtok_r(NULL, "/", &strtokState))==NULL)
      continue;
    if ((prefix=strtok_r(NULL, "\n", &strtokState))==NULL)
      continue;
    
    addNodeInternal(xaton(ip), atoi(prefix), cc);
  }
  fclose(fd);
}

/* ************************************************************************* */

char *ip2CountryCode(uint32_t ip)
{
  IPNode *p=Head;
  int i, b;
  char *cc="";

  i=0;
  while (p!=NULL) {
    if (p->cc[0]!=0)
    {
      cc=p->cc;
      printf("%s/%d ", cc, i);
    }
    b=(ip>>(31-i)) & 0x1;
    p=p->b[b];
    i++;
  }
  return cc;
}

/* ************************************************************************* */

void usage(void)
{
  fprintf(stderr, "lookuptest %s\n", VERSION);
  fprintf(stderr, "Usage: lookuptest [OPTION]... [IP]...\n");
  fprintf(stderr, "Lookup country codes for specified IPs.\n");
  fprintf(stderr, "If no IPs are specified on the commandline a list of IPs is read from stdin.\n\n");
  fprintf(stderr, "  -t fname  Read mapping table from fname\n\n");
  fprintf(stderr, "Example: ./lookuptest 19.203.239.24, returns:\n\n");
  fprintf(stderr, "19.203.239.24: ***/0 US/6 IL/29\n\n");
  fprintf(stderr, "  Which means the address, 19.203.239.24 is contained in the root block ***/0 (always).\n");
  fprintf(stderr, "  More specifically it is contained in a /6 listed as in the US and\n");
  fprintf(stderr, "  most specifically it is in a /29 which is listed as in IL (Israel).\n\n");
  exit(EXIT_FAILURE);
}

/* ************************************************************************* */

void parseOptions(int argc, char *argv[])
{
  int c;

  while ((c=getopt(argc, argv, "?ht:"))!=-1) {
    switch (c) {
      case 't':
        OptTableFilename=optarg;
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
  int i;

  parseOptions(argc, argv);

  initIPCountryTable();

  if (optind>=argc) {
    while (!feof(stdin)) {
      char buff[64];
      
      fgets(buff, sizeof(buff)-1, stdin);
      if (!feof(stdin)) {
        ip2CountryCode(xaton(buff));
        printf("\n");
      }
    }
  }
  else {
    for (i=optind; i<argc; i++) {
      printf("%s: ", argv[i]);
      ip2CountryCode(xaton(argv[i]));
      printf("\n");
    }
  }
  
  exit(EXIT_SUCCESS);
}

