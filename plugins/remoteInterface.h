/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *
 *  			  Centro SERRA, University of Pisa
 *  			  http://www.ntop.org/
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

#ifndef _REMOTE_INTERFACE_H_
#define _REMOTE_INTERFACE_H_

#define HELLO_CMD              "hello"
#define GETHOST_CMD            "gethostbyindex"     /* gethostbyindex <index> */
#define FIND_HOST_BY_IP_CMD    "findhostbyip"       /* findhostbyip ip_address */
#define FIND_HOST_BY_MAC_CMD   "findhostbymac"      /* findhostbymac mac_address */

#define OK_RC                      "200 OK"
#define UNKNOWN_COMMAND_RC         "404 Unknown Command"
#define WRONG_COMMAND_SYNTAX_RC    "405 Wrong Command Syntax"
#define OUT_OF_RANGE_RC            "406 Out of Range"
#define EMPTY_SLOT_RC              "407 Empty Slot"
#define CONNECTION_REFUSED_RC      "408 Connection Refused"

#define NTOP_PATH		   "/var/run/ntop.sock"
#define DEBUG			   1

#endif /* _REMOTE_INTERFACE_H_ */
