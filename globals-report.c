/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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

#define _GLOBALS_REPORT_C_

#include "ntop.h"
#include "globals-report.h"

#ifndef MICRO_NTOP
int maxNumLines = MAX_NUM_TABLE_ROWS;
int sortSendMode = 0;
short sortFilter;

/* Threads */

/* TCP Wrappers */
#ifdef HAVE_LIBWRAP
int allow_severity = LOG_INFO;
int deny_severity  = LOG_WARNING;
#endif /* HAVE_LIBWRAP */

#endif /* MICRO_NTOP */

int webPort = NTOP_DEFAULT_WEB_PORT;
int refreshRate = 0;
int localAddrFlag = 1;
int actualReportDeviceId;
short screenNumber, columnSort;
int sock, newSock;
#ifdef HAVE_OPENSSL
int sock_ssl;
#endif
