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

#include "ntop.h"
#include "globals-report.h"

NtopGlobals myGlobals;

#ifdef WIN32
char *version, *osName, *author, *buildDate;
#endif

void initNtopGlobals() {
  u_short _mtuSize[] = {
    8232,   	/* no link-layer encapsulation */
    /* 1500 + 14 bytes header 
       Courtesy of Andreas Pfaller <a.pfaller@pop.gun.de> */
    1500+sizeof(struct ether_header),   /* Ethernet (10Mb) */
    UNKNOWN_MTU,  /* Experimental Ethernet (3Mb) */
    UNKNOWN_MTU,  /* Amateur Radio AX.25 */
    17914,	/* Proteon ProNET Token Ring */
    UNKNOWN_MTU,  /* Chaos */
    4096+sizeof(struct tokenRing_header),	        /* IEEE 802 Networks */
    UNKNOWN_MTU,  /* ARCNET */
    UNKNOWN_MTU,  /* Serial Line IP */
    UNKNOWN_MTU,  /* Point-to-point Protocol */
    4470,	        /* FDDI - Courtesy of Richard Parvass <Richard.Parvass@ReckittBenckiser.com> */
    9180,         /* LLC/SNAP encapsulated atm */
    UNKNOWN_MTU,  /* raw IP */
    UNKNOWN_MTU,  /* BSD/OS Serial Line IP */
    UNKNOWN_MTU	/* BSD/OS Point-to-point Protocol */
  };

  u_short _headerSize[] = {
    NULL_HDRLEN,  /* no link-layer encapsulation */
    sizeof(struct ether_header),	        /* Ethernet (10Mb) */
    UNKNOWN_MTU,  /* Experimental Ethernet (3Mb) */
    UNKNOWN_MTU,  /* Amateur Rdio AX.25 */
    sizeof(struct tokenRing_header),	/* Proteon ProNET Token Ring */
    UNKNOWN_MTU,  /* Chaos */
    1492,	        /* IEEE 802 Networks */
    UNKNOWN_MTU,  /* ARCNET */
    UNKNOWN_MTU,  /* Serial Line IP */
    PPP_HDRLEN,   /* Point-to-point Protocol */
    sizeof(struct fddi_header),	        /* FDDI */
    0,            /* LLC/SNAP encapsulated atm */
    0,            /* raw IP */
    UNKNOWN_MTU,  /* BSD/OS Serial Line IP */
    UNKNOWN_MTU	/* BSD/OS Point-to-point Protocol */
  };

  static char *_dataFileDirs[]   = { ".", DATAFILE_DIR, NULL };
  static char *_pluginDirs[]     = { "./plugins", PLUGIN_DIR, NULL };
  static char *_configFileDirs[] = { ".", CONFIGFILE_DIR, "/etc", NULL };

  /* ****************** */
  
  memset(&myGlobals, 0, sizeof(myGlobals));
  myGlobals.mtuSize        = _mtuSize;
  myGlobals.headerSize     = _headerSize;
  myGlobals.dataFileDirs   = _dataFileDirs;
  myGlobals.pluginDirs     = _pluginDirs;
  myGlobals.configFileDirs = _configFileDirs;
  myGlobals.separator      = "&nbsp;";
#ifdef HAVE_GDCHART
  myGlobals.throughput_chart_type = GDC_AREA;
#endif    
}
