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

$ gcc -o inetnum2countryalloc inetnum2countryalloc.c

 */

#define VERSION "1.0.2"

#include <stdio.h>
#include <string.h>


typedef unsigned int uint32;

int iCount=0, oCount=0;

uint32 xaton(char *s)
{
  uint32 a, b, c, d;

  if (4!=sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d))
    return 0;
  return ((a&0xFF)<<24)|((b&0xFF)<<16)|((c&0xFF)<<8)|(d&0xFF);
}

#define FLAG_HAVE_INETNUM 1
#define FLAG_HAVE_COUNTRY 2

void convert2Table(void)
{
  char buff[256];
  int flags=0;
  char ip1s[32], ip2s[32], country[4];
  uint32 ip1, ip2;
  
  while (!feof(stdin)) {
    if (fgets(buff, sizeof(buff), stdin)==NULL)
      continue;

    iCount++;

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
    else if (strstr(buff, "not allocated to APNIC"))
      flags=0;
    else if (buff[0]=='\n')
      flags=0;

    if (flags==(FLAG_HAVE_INETNUM | FLAG_HAVE_COUNTRY)) {
      printf("apf|%s|ipv4|%s|%u|x|x\n", country, ip1s, ip2-ip1+1);
      flags=0;
      oCount++;
    }
  }
}

int main(int argc, char *argv[]) 
{
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
    printf("ntop (http://www.ntop.org) ip2cc inetnum2countryalloc, version %s\n\n", VERSION);
    printf("Function: Converts alternate address file, e.g. ripe.db.inetnum.gz to standard file for prefixtablegen\n\n");
    printf("Usage: zcat xxxxalt.data.gz | ./inetnum2countryalloc [-help] [-quiet] > 0_xxxxalt.data\n\n");
    exit(0);
  }

  if(quiet) printf("ntop (http://www.ntop.org) ip2cc inetnum2countryalloc, version %s\n\n", VERSION);

  convert2Table();

  if(quiet) printf("Done! (%d records read, %d output)\n\n", iCount, oCount);

  exit (0);
}

    
