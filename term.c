/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		 	    http://www.ntop.org/
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

#include "ntop.h"



/* ******************************* */

void termIPServices(void) {
  int i;

  for(i=0; i<SERVICE_HASH_SIZE; i++) {
    if(udpSvc[i] != NULL) {
      free(udpSvc[i]->name);
      free(udpSvc[i]);
    }

    if(tcpSvc[i] != NULL) {
      free(tcpSvc[i]->name);
      free(tcpSvc[i]);
    }
  }
}


/* ******************************* */

void termIPSessions(void) {
  int i;

  for(i=0; i<HASHNAMESIZE; i++) {
    if(tcpSession[i] != NULL) 
      free(tcpSession[i]);    

    if(udpSession[i] != NULL) 
      free(udpSession[i]);

    numTcpSessions = numUdpSessions = 0;

    while (fragmentList != NULL)
      deleteFragment(fragmentList);
  }
}
