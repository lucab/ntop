/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *
 *		  	  Centro SERRA, University of Pisa
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


extern int maxNumLines, idleFlag, percentMode, localAddrFlag, refreshRate;
extern int webPort, actualReportDeviceId;

extern int sock, newSock;
#ifdef HAVE_OPENSSL
extern int sock_ssl;
#endif

extern short screenNumber, columnSort;

/* Threads */
#ifdef MULTITHREADED
extern pthread_t logFileLoopThreadId;
#endif

int cmpFctn(const void *_a, const void *_b);
extern int reportValues(time_t*);
extern void updateCursesStats();
extern void initializeWeb();
extern void handleDbSupport(char* addr, int*);
extern void switchNwInterface(int);

extern void getProtocolDataSent(TrafficCounter *c, TrafficCounter *d,
				TrafficCounter *e, HostTraffic *el);
extern void getProtocolDataReceived(TrafficCounter *c, TrafficCounter *d,
				    TrafficCounter *e, HostTraffic *el);
extern char formatStatus(HostTraffic *el);
extern void initReports();

extern void formatUsageCounter(UsageCounter usageCtr);
extern void usage();
extern void printDebugInfo();

extern void initAccessLog();
extern void termAccessLog();
