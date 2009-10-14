/*
 *  Copyright (C) 2009 Luca Deri <deri@ntop.org>
 *
 * 		       http://www.ntop.org/
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

void notifyEvent(EventType evt, HostTraffic *el, IPSession *session) {
  char *event = NULL;
  
  switch(evt) {
  case hostCreation:
    event = "Host created";
    break;
  case hostDeletion:
    event = "Host deleted";
    break;
  case sessionCreation:
    event = "IP session created";
    break;
  case sessionDeletion:
    event = "IP session deleted";
    break;
  case hostFlagged:
    event = "Host flagged";
    break;
  }

  if(el) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY, "[event: %s][target: %s/%s]",
	       event,
	       el->ethAddressString,
	       el->hostNumIpAddress);	       
  }

}
