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
#include <ctype.h>
#include "p2clib.h"

/* ************************************************************************* */

char *strtolower(char *s) {
  while (*s) {
    *s=tolower(*s);
    s++;
  }
  
  return(s);
}

/* ************************************************************************* */

char *strtoupper(char *s) {
  while (*s) {
    *s=toupper(*s);
    s++;
  }
  
  return(s);
}

/* ************************************************************************* */

u_int32_t xaton(char *s)
{
  u_int32_t a, b, c, d;

  if (4!=sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d))
    return 0;
  return ((a&0xFF)<<24)|((b&0xFF)<<16)|((c&0xFF)<<8)|(d&0xFF);
}

/* ************************************************************************* */

char *xntoa(u_int32_t ip, char *result, int len)
{
  snprintf(result, len, "%d.%d.%d.%d",
           (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);
  return result;
}

