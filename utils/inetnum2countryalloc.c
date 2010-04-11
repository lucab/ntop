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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "p2clib.h"

#define VERSION "2.0"

#define FLAG_HAVE_INETNUM 1
#define FLAG_HAVE_COUNTRY 2

/* ************************************************************************* */

void convert2Table(void)
{
  char buff[256];
  int flags=0;
  char ip1s[32], ip2s[32], country[4];
  uint32_t ip1, ip2;
  
  while (!feof(stdin)) {
    if (fgets(buff, sizeof(buff), stdin)==NULL)
      continue;

    if ((2==sscanf(buff, "inetnum:%*[ ] %31[0-9.] - %31[0-9.]", ip1s, ip2s)) ||
        (2==sscanf(buff, "*in: %31[0-9.] - %31[0-9.]", ip1s, ip2s))) {
      ip1=xaton(ip1s);
      ip2=xaton(ip2s);
      if (ip2>ip1)
        flags=FLAG_HAVE_INETNUM;
    }
    else if (1==sscanf(buff, "country: %3s", country))
      flags|=FLAG_HAVE_COUNTRY;
    else if (1==sscanf(buff, "*cy: %3s", country))
      flags|=FLAG_HAVE_COUNTRY;
    else if (strstr(buff, "not allocated to APNIC") ||
             strstr(buff, "Not allocated by APNIC") ||
             strstr(buff, "Early registration addresses"))
      flags=0;
    else if (buff[0]=='\n')
      flags=0;

    if (flags==(FLAG_HAVE_INETNUM | FLAG_HAVE_COUNTRY)) {
      printf("apf|%s|ipv4|%s|%u|x|x\n", country, ip1s, ip2-ip1+1);
      flags=0;
    }
  }
}

/* ************************************************************************* */

void usage(void)
{
  fprintf(stderr, "inetnum2countryalloc %s\n", VERSION);
  fprintf(stderr, "Usage: inetnum2countryalloc\n");
  fprintf(stderr, "Convert whois address file (e.g ripe.db.inetnum.gz) to standard\n");
  fprintf(stderr, "format which can be processed by prefixtablegen\n\n");
  fprintf(stderr, "Example:\n");
  fprintf(stderr, "  zcat ripe.db.inetnum.gz | ./inetnum2countryalloc >ripe.inetnum.data\n");
  exit(EXIT_FAILURE);
}

/* ************************************************************************* */

void parseOptions(int argc, char *argv[])
{
  int c;

  while ((c=getopt(argc, argv, "?h"))!=-1) {
    switch (c) {
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
  parseOptions(argc, argv);
  
  convert2Table();
  exit (EXIT_SUCCESS);
}

    
