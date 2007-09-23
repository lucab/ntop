/*
 *  Copyright (C) 1998-2007 Luca Deri <deri@ntop.org>
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
#include <getopt.h>

void usage(char *progName) {
  printf("Usage: %s -f <file>.gdbm [-s <key>=<value>] [-l] [-d <key>]\n"
	 "       -s <key>=<value>     | Set a key to the specified value\n"
	 "       -l                   | List all keys/values\n"
	 "       -d <key>             | Delete the specified key\n",
	 progName);
  exit(-1);
}

int main(int argc, char *argv[])
{
  GDBM_FILE gdbm_file = NULL;
  datum key_data, data_data, return_data;
  char c, *key = NULL, *value = NULL;

  while((c = getopt(argc, argv, "f:s:ld:")) != -1) {
    switch(c) {
    case 'f':
      gdbm_file = gdbm_open(optarg, 0, GDBM_WRCREAT, 00664, NULL);
  
      if(gdbm_file == NULL) {
	printf("Database open failed: %s\n", gdbm_strerror(gdbm_errno));
	exit(-1);    
      }
      break;

    case 's':
      key = strtok(optarg, "=");
      if(key) value = strtok(NULL, "\n");
      if((!key) || (!value)) {
        printf("Missing key or value\n");
        exit(-1);
      }
      
      if(gdbm_file == NULL) {
        printf("Please specify -f as first option\n");
        exit(-1);
      }

      key_data.dptr = key;
      key_data.dsize = strlen(key_data.dptr)+1;
      data_data.dptr = value;
      data_data.dsize = strlen(data_data.dptr)+1;
      
      if(gdbm_store(gdbm_file, key_data, data_data, GDBM_REPLACE) != 0)
	printf("Error while setting data: %s\n", gdbm_strerror(gdbm_errno));
      break;

    case 'd':
      if(gdbm_file == NULL) {
        printf("Please specify -f as first option\n");
        exit(-1);
      }

      key_data.dptr = optarg;
      key_data.dsize = strlen(key_data.dptr)+1;

      if(gdbm_delete(gdbm_file, key_data) != 0)
        printf("Error while deleting key: %s\n", gdbm_strerror(gdbm_errno));
      break;

    case 'l':
      if(gdbm_file == NULL) {
        printf("Please specify -f as first option\n");
        exit(-1);
      }
      
      data_data = gdbm_firstkey(gdbm_file);

      while(data_data.dptr != NULL) {
        key_data = data_data;
	return_data = gdbm_fetch(gdbm_file, key_data);
	printf("%s=%s\n", key_data.dptr, return_data.dptr);
	free(return_data.dptr);
	data_data = gdbm_nextkey(gdbm_file, key_data);
	free(key_data.dptr);
      }

      break;
    }
  }

  if(gdbm_file == NULL)
    usage(argv[0]);
  else
    gdbm_close(gdbm_file);

  return(0);
}
