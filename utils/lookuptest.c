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

$ gcc -o lookuptest lookuptest.c

 */

#define VERSION "1.0"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>


#define QUAD2IP(a,b,c,d) ((a)<<24 | (b)<<16 | (c<<8) | (d))
#define PREFIX2MASK(n) (~0UL<<(32-(n)))

typedef struct IPNode 
{
  struct IPNode *b[2];
  char cc[4];
} IPNode;

IPNode *Head;

/* ******************************************************************* */

u_int32_t xaton(char *s)
{
  u_int32_t a, b, c, d;

  if (4!=sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d))
    return 0;
  return ((a&0xFF)<<24)|((b&0xFF)<<16)|((c&0xFF)<<8)|(d&0xFF);
}

/* ******************************************************************* */

char *xntoa(u_int32_t ip, char *result, int len)
{
  snprintf(result, len, "%d.%d.%d.%d",
           (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
  return result;
}

/* ******************************************************************* */
  
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
      memset(p2, 0, sizeof(IPNode));
      p1->b[b]=p2;
    }
    else
      p2=p1->b[b];
    
    p1=p2;
  }
  if (p2->cc[0]==0) {
    strcpy(p2->cc, country);
  }
}

/* ******************************************************************* */

char *ip2CountryCode(u_int32_t ip)
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

/* ******************************************************************* */

void initIPCountryTable(void)
{
  FILE *fd;
  
  if ((Head=malloc(sizeof(IPNode)))==NULL)
    exit(1);
  strcpy(Head->cc, "***");
  Head->b[0]=NULL;
  Head->b[1]=NULL;  

  fd = fopen("p2c.opt.table", "r");

  if (fd!=NULL) {
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
}

/* ******************************************************************* */

int main(int argc, char *argv[])
{
  int i, usage=0, first=1, quiet=1;

  if ( (argc >= 2) && 
       ( (strncasecmp("-h", argv[1], 2) == 0) ||
         (strncasecmp("--h", argv[1], 3) == 0) ) ) {
    usage=1;
  } else if ( (argc >= 2) && 
       ( (strncasecmp("-q", argv[1], 2) == 0) ||
         (strncasecmp("--q", argv[1], 3) == 0) ) ) {
    quiet=0;
    first++;
  }

  if ( (usage) || (argc < 2) ) {
    printf("ntop (http://www.ntop.org) ip2cc lookuptest, version %s\n\n", VERSION);
    printf("Function: Converts ip address(es) to country codes\n\n");
    printf("Usage: lookuptest [-help] [-quiet] address [address...]\n\n");
    printf("Example: ./lookuptest 19.203.239.24, returns:\n\n");
    printf("19.203.239.24: ***/0 US/6 IL/29\n\n");
    printf("  Which means the address, 19.203.239.24 is contained in the root block ***/0 (always).\n");
    printf("  More specifically it is contained in a /6 listed as in the US and\n");
    printf("  most specifically it is in a /29 which is listed as in IL (Israel).\n\n");
    exit(0);
  }

  if(quiet) printf("ntop (http://www.ntop.org) ip2cc lookuptest, version %s\n\n", VERSION);
  if(quiet) printf("Loading table...\n");
  initIPCountryTable();

  if(quiet) printf("Processing addresses...\n");
  for (i=first; i<argc; i++) {
    printf("    %s: ", argv[i]);
    ip2CountryCode(xaton(argv[i]));
    printf("\n");
  }
  if(quiet) printf("Done!\n\n");
  exit(0);
}

