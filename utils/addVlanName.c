/*
 *  Copyright (C) 1998-2005 Luca Deri <deri@ntop.org>
 *                      
 *		 	  http://www.ntop.org/
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
#include <stdio.h>
#include <gdbm.h>
#include <stdlib.h>
#include <string.h>

void usage(char *progName) {
  printf("Usage: %s <VLAN Id> <symbolic VLAN name> <prefsCache.db file>\n", progName);
  printf("Example: %s 2001 \"Local Vlan\" "
	 "/usr/people/luca/ntop/prefsCache.db\n", progName);
  exit(-1);
}

int main(int argc, char *argv[])
{
  GDBM_FILE gdbm_file;
  datum key_data, data_data;
  char key[64];

  if(argc != 4) {
    usage(argv[0]);
  }

  gdbm_file = gdbm_open (argv[3], 0, GDBM_WRCREAT, 00664, NULL);
  
  if(gdbm_file == NULL) {
    printf("Database open failed: %s\n", gdbm_strerror(gdbm_errno));
    exit(-1);    
  }

  snprintf(key, sizeof(key), "vlan.%d", atoi(argv[1]));

  key_data.dptr = key;
  key_data.dsize = strlen(key_data.dptr)+1;
  data_data.dptr = argv[2];
  data_data.dsize = strlen(data_data.dptr)+1;

  if(gdbm_store(gdbm_file, key_data, data_data, GDBM_REPLACE) != 0)
    printf("Error while adding data: %s\n", gdbm_strerror(gdbm_errno));

  gdbm_close(gdbm_file);

  return(0);
}
