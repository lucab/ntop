/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                        Portions by Stefano Suin <stefano@ntop.org>
 *                      
 * 			  Centro SERRA, University of Pisa
 * 			  http://www.ntop.org/
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

typedef struct {
  unsigned long vendorId;
  char* vendorName;
} VendorInfo;


/* *********************************************************

 1) Download http://standards.ieee.org/regauth/oui/oui.txt  
 2) do 'grep "(hex)" oui.txt | cut -c1-8,9,19- | more'
  

 * ****************************************************** */



/* *********************************************************
 * 
 * The information contained in this file 
 * has been provided by Ethernet-codes@Cavebear.com.
 *
 * http://www.cavebear.com/CaveBear/Ethernet/vendor.html
 *
 * Courtesy of "William R. McDonough" <wrmcd@wilmcd.com>.
 *
 * ******************************************************
 */

#include "ntop.h"

/* This file can be automatically generated via make vt */
#include "vendortable.h"


static VendorInfo specialMacInfo[] = {
  { 0x01000C, "Cisco CDPD/VTP" },
  { 0x010010, "Hughes Lan" },
  { 0x01001D, "Cabletron" },
  { 0x01003C, "Auspex Systems" },
  { 0x01005E, "DoD Internet Multicast" },
  { 0x010081, "Synoptics" },
  { 0x012025, "Control Tech. Inc." },
  { 0x018024, "Kalpana Etherswitch" },
  { 0x0180C2, "Bridge Sp. Tree/OSI Route" },
  { 0x01DD00, "UngermannBass" },
  { 0x01DD01, "UngermannBass" },
  { 0x030000, "NetBios" },
  { 0x030040, "NetBios" },
  { 0x090002, "Vitalink" },
  { 0x090007, "AppleTalk" },
  { 0x090009, "HP Probe" },
  { 0x09000D, "ICL" },
  { 0x09001E, "Apollo" },
  { 0x090026, "Vitalink" },
  { 0x09002B, "DEC" },
  { 0x090039, "Spider Systems" },
  { 0x09004C, "BICC" },
  { 0x09004E, "Novell IPX" },
  { 0x090056, "Stanford" },
  { 0x09006A, "TOP NetBIOS" },
  { 0x090077, "Retix" },
  { 0x09007C, "Vitalink" },
  { 0x090087, "Xyplex" },
  { 0x0D1E15, "HP" },
  { 0x333300, "IPv6" },
  { 0xAB0000, "DEC MOP/DECNET" },
  { 0xAB0003, "DEC LAT" },
  { 0xAB0004, "DEC VAX" },
  { 0xCF0000, "Ethernet CTP" },
  { 0xFFFF00, "Lantastic" },
  { 0xFFFF01, "Lantastic" },
  { 0xFFFFFF, "Ethernet Broadcast" },
  { 0x0, NULL }
};

/* http://www.isi.edu/in-notes/iana/assignments/novell-sap-numbers */
static VendorInfo ipxSAP[] = {
  { 0x0001,	"User" },
  { 0x0002,	"User Group" },
  { 0x0003,	"Print Queue" },
  { 0x0004,	"File server" },
  { 0x0005,	"Job server" },
  { 0x0007,	"Print server" },
  { 0x0008,	"Archive server" },
  { 0x0009,	"Archive server" },
  { 0x000a,	"Job queue" },
  { 0x000b,	"Administration" },
  { 0x0021,	"NAS SNA gateway" },
  { 0x0024,	"Remote bridge" },
  { 0x0026,	"Bridge server" },
  { 0x0027,	"TCP/IP gateway" },
  { 0x002d,	"Time Synchronization VAP" },
  { 0x002e,	"Archive Server Dynamic SAP" },
  { 0x0047,	"Advertising print server" },
  { 0x004b,	"Btrieve VAP 5.0" },
  { 0x004c,	"SQL VAP" },
  { 0x0050,	"Btrieve VAP" },
  { 0x0053,	"Print Queue VAP" },
  { 0x007a,	"TES NetWare for VMS" },
  { 0x0098,	"NetWare access server" },
  { 0x009a,	"Named Pipes server" },
  { 0x009e,	"Portable NetWare Unix" },
  { 0x0107,	"NetWare 386" },
  { 0x0111,	"Test server" },
  { 0x0133,	"NetWare Name Service" },
  { 0x0166,	"NetWare management" },
  { 0x023f,	"SMS Testing and Development" },
  { 0x026a,	"NetWare management" },
  { 0x026b,	"Time synchronization" },
  { 0x027b,	"NetWare Management Agent" },
  { 0x0278,	"NetWare Directory server" },
  { 0x030c,	"HP LaserJet / Quick Silver" },
  { 0x0355,	"Arcada Software" },
  { 0x0361,	"NETINELO" },
  { 0x037e,	"Powerchute UPS Monitoring" },
  { 0x03e1,	"UnixWare Application Server" },
  { 0x044c,	"Archive" },
  { 0x055d,	"Attachmate SNA gateway" },
  { 0x0610,	"Adaptec SCSI Management" },
  { 0x0640,	"NT Server-RPC/GW for NW/Win95 User Level Sec" },
  { 0x064e,	"NT Server-IIS" },
  { 0x0810,	"ELAN License Server Demo" },
  { 0x8002,	"Intel NetPort Print Server" },
  { 0x0000,	NULL }
};



VendorInfo* vendorHash[VENDORHASHNAMESIZE];
VendorInfo* specialMacHash[SHORTHASHNAMESIZE];
VendorInfo* ipxSAPhash[VENDORHASHNAMESIZE];



/* *********************************** */

static void addMacTableEntry(VendorInfo* theMacHash[], 
			     VendorInfo* entry, 
			     u_int tableLen) {
  u_int idx;

  idx = (u_int)(entry->vendorId % tableLen);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%d %x '%s'\n", idx,
	 entry->vendorId,
	 entry->vendorName);
#endif

  for(;;) {
    if(theMacHash[idx] == NULL) {      
      theMacHash[idx] = entry;
      break;
    }    
    idx = (idx+1)%tableLen;
  }
}

/* *********************************** */

char* getMacInfo(VendorInfo* vendorTable[], 
		 u_char* ethAddress,
		 u_int tableLen, short encodeString) {
  u_int idx;
  unsigned long vendorValue;
  VendorInfo* cursor;

  vendorValue = 256*256*(unsigned long)ethAddress[0] 
    + 256*(unsigned long)ethAddress[1] 
    + (unsigned long)ethAddress[2];
  idx = (u_int)((u_int)vendorValue % tableLen);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%d %ld\n", idx, vendorValue);
#endif

  for(;;) {
    cursor = vendorTable[idx];
    
    if(vendorTable[idx] == NULL) {
      /* Unknown vendor */
      return("");
    } else if(vendorTable[idx] != NULL) {
      if(vendorTable[idx]->vendorId == vendorValue) {
	if(encodeString) {
	  static char vendorName[256];
	  int a, b;

	  for(a=0, b=0; vendorTable[idx]->vendorName[a] != '\0'; a++)
	    if(vendorTable[idx]->vendorName[a] == ' ') {
	      vendorName[b++] = '&';
	      vendorName[b++] = 'n';
	      vendorName[b++] = 'b';
	      vendorName[b++] = 's';
	      vendorName[b++] = 'p';
	      vendorName[b++] = ';';
	    } else
	      vendorName[b++] = vendorTable[idx]->vendorName[a];

	  vendorName[b] = '\0';	    
	  return(vendorName);
	} else
	  return(vendorTable[idx]->vendorName);

      }
    }

    idx = (idx+1)%tableLen;
  }
}

/* *********************************** */

char* getVendorInfo(u_char* ethAddress, short encodeString) {
  return(getMacInfo(vendorHash, ethAddress, VENDORHASHNAMESIZE, encodeString));
}

/* *********************************** */

char* getSAPInfo(u_int16_t sapInfo, short encodeString) {
  u_int idx;
  unsigned long vendorValue = (unsigned long)sapInfo;
  VendorInfo* cursor;

  idx = (u_int)((u_int)sapInfo % VENDORHASHNAMESIZE);

  for(;;) {
    cursor = ipxSAPhash[idx];
    
    if(ipxSAPhash[idx] == NULL) {
      /* Unknown vendor */
      return("");
    } else if(ipxSAPhash[idx] != NULL) {
      if(ipxSAPhash[idx]->vendorId == vendorValue) {
	if(encodeString) {
	  static char vendorName[256];
	  int a, b;

	  for(a=0, b=0; ipxSAPhash[idx]->vendorName[a] != '\0'; a++)
	    if(ipxSAPhash[idx]->vendorName[a] == ' ') {
	      vendorName[b++] = '&';
	      vendorName[b++] = 'n';
	      vendorName[b++] = 'b';
	      vendorName[b++] = 's';
	      vendorName[b++] = 'p';
	      vendorName[b++] = ';';
	    } else
	      vendorName[b++] = ipxSAPhash[idx]->vendorName[a];

	  vendorName[b] = '\0';	    
	  return(vendorName);
	} else
	  return(ipxSAPhash[idx]->vendorName);

      }
    }

    idx = (idx+1)%VENDORHASHNAMESIZE;
  }

  return(""); /* NOTREACHED */
}

/* *********************************** */

char* getSpecialMacInfo(HostTraffic* el, short encodeString) {
#ifdef HAVE_GDBM_H
  datum key_data, data_data;
  static char tmpBuf[96];
#endif
  char* ret = getMacInfo(specialMacHash, el->ethAddress, SHORTHASHNAMESIZE, encodeString);

  if((ret != NULL) && (ret[0] != '\0'))
    return(ret);
  
#ifndef HAVE_GDBM_H
  return("");
#else

  /* Search the specified MAC address into 'ntop.db' */
  strncpy(tmpBuf, el->ethAddressString, sizeof(tmpBuf));
  key_data.dptr = tmpBuf;
  key_data.dsize = strlen(tmpBuf)+1;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Fetching '%s'\n", tmpBuf);
#endif

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "getSpecialMacInfo");
#endif 

  data_data = gdbm_fetch(gdbm_file, key_data);

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  if(data_data.dptr != NULL) {    
    strncpy(tmpBuf, data_data.dptr, sizeof(tmpBuf));
    free(data_data.dptr);
    return(tmpBuf);
  } else
    return("");

#endif /* HAVE_GDBM_H */
}

/* *********************************** */

void createVendorTable() 
{
  int idx;

  for(idx=0; vendorInfo[idx].vendorName != NULL; idx++)
    addMacTableEntry(vendorHash, &vendorInfo[idx], VENDORHASHNAMESIZE);

  for(idx=0; specialMacInfo[idx].vendorName != NULL; idx++)
    addMacTableEntry(specialMacHash, &specialMacInfo[idx], SHORTHASHNAMESIZE);

  for(idx=0; ipxSAP[idx].vendorName != NULL; idx++)
    addMacTableEntry(ipxSAPhash, &ipxSAP[idx], VENDORHASHNAMESIZE);
}

