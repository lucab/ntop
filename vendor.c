/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *                      
 * 			    http://www.ntop.org/
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

/*
 * NOTE: About the tables in this program and vendortable.h...
 *
 *   IPX SAP
 *       The official list is maintained by iana at
 *             http://www.iana.org/assignments/novell-sap-numbers
 *
 *       While there is Makefile code to download and rebuild the structure (make dnsapt sapt),
 *       as of 01-2003, it doesn't work.
 *
 *       The file format has been changed, the sapt.sed file is lost, and besides it builds a 
 *       saptable.h file which you would manually have to insert into vendor.c.
 *
 *       OTOP, Novell doesn't change things very often.
 *
 *   Vendor
 *       The official list is updated daily at http://standards.ieee.org/regauth/oui/oui.txt  
 *       The vendor table data does change, frequently, albeit irrelevantly to most of us.
 *       The ntop distribution file, vendortable.h, is updated infrequently.
 *
 *       To update (if say, you're seeing a lot of unknown values):
 *
 *           1) Download the list.
 *           2) Run the vt.sed script on the downloaded file to create vendortable.h
 *
 *       Both of these steps are in Makefile:
 *
 *           mkdir Internet
 *           make dnvt vt
 *
 *       Warning: the mac address list frequently discussed on the 'net at 
 *       http://www.cavebear.com/CaveBear/Ethernet/vendor.html hasn't been 
 *       updated since 1999.
 *
 *   Special MAC
 *       The special mac table is referenced - getHostInfo() in hash.c calls 
 *       getSpecialMacInfo() in util.c - each time a new (pseudo) local host
 *       is found.
 *
 *       So, optimizing the table size after the table is updated is reasonable,
 *       especially for a large network with many hosts coming and going.
 *
 *       I (Burton) am unaware of any official or even pseudo-offical list.
 */

/*
 * NOTE: About optimzing hash sizes...
 *
 *   See the #define TEST_HASHSIZE_xxxxxx's below.
 *
 *   Enabling it (esp. for vendor table) will run A LONG TIME, as it tests each possible
 *   odd value from some low number up to whatever the MAX_ value is in globals-defines.h.
 *   (Testing will stop if a zero collision value is found).
 *
 *   Testing will produce a running list, showing the best so far.
 *
 *       TEST_HASHSIZE: Testing specialMacHash...wait
 *       TEST_HASHSIZE: specialMacHash  51  16
 *       TEST_HASHSIZE: specialMacHash  53  13
 *       TEST_HASHSIZE: specialMacHash  55  11
 *       TEST_HASHSIZE: specialMacHash  65   8
 *       TEST_HASHSIZE: specialMacHash  79   5
 *       TEST_HASHSIZE: specialMacHash 125   3
 *       TEST_HASHSIZE: specialMacHash 133   2
 *       TEST_HASHSIZE: specialMacHash 141   1
 *       TEST_HASHSIZE: specialMacHash BEST is 0 collisions, size 167
 *
 *   The ipxsap and vendor tables are referenced only for reporting - so a few collisions
 *   isn't a huge deal.
 */

typedef struct {
  unsigned long vendorId;
  char* vendorName;
} VendorInfo;


#include "ntop.h"
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

/* http://www.iana.org/assignments/novell-sap-numbers */
static VendorInfo ipxSAP[] = {
  { 0x0000,	"Unknown" },
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



VendorInfo* vendorHash[MAX_VENDOR_NAME_HASH];
VendorInfo* specialMacHash[MAX_SPECIALMAC_NAME_HASH];
VendorInfo* ipxSAPhash[MAX_IPXSAP_NAME_HASH];



/* *********************************** */

static int addMacTableEntry(VendorInfo* theMacHash[], 
			     VendorInfo* entry, 
			     u_int tableLen) {
  u_int idx;
  unsigned long vendorValue;
  int hashLoadCollisions=0;

#ifdef PARM_USE_MACHASH_INVERT
  vendorValue = 256*256*(unsigned long)(entry->vendorId & 0xff)
    + 256*(unsigned long)((entry->vendorId >> 8) & 0xff)
    + (unsigned long)((entry->vendorId >> 16) & 0xff);
#else
  idx = (u_int)(entry->vendorId % tableLen);
#endif
  idx = (u_int)((u_int)vendorValue % tableLen);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: addMacTableEntry(%06x, %s) gives %ld (mod %d = %d)\n", 
	 entry->vendorId,
	 entry->vendorName,
         vendorValue,
         tableLen,
         idx);
#endif

  /* Count # of collisions during load - only ONCE per item */
  if(theMacHash[idx] != NULL) {
      hashLoadCollisions++;
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: HashLoad Collision - %d %x '%s\n", 
                                   idx, entry->vendorId, entry->vendorName);
#endif
  }

  for(;;) {
    if(theMacHash[idx] == NULL) {      
      theMacHash[idx] = entry;
      break;
    }    
    idx = (idx+1)%tableLen;
  }

  return hashLoadCollisions;
}

/* *********************************** */

static char* getMacInfo(VendorInfo* vendorTable[], 
			u_char* ethAddress,
			u_int tableLen, short encodeString) {
  u_int idx;
  unsigned long vendorValue;
#ifdef PARM_USE_MACHASH_INVERT
  unsigned long vendorValueInvert;
#endif
  VendorInfo* cursor;
  int hasCollision=0;

  vendorValue = 256*256*(unsigned long)ethAddress[0] 
    + 256*(unsigned long)ethAddress[1] 
    + (unsigned long)ethAddress[2];
#ifdef PARM_USE_MACHASH_INVERT
  vendorValueInvert = 256*256*(unsigned long)ethAddress[2] 
    + 256*(unsigned long)ethAddress[1] 
    + (unsigned long)ethAddress[0];
  idx = (u_int)((u_int)vendorValueInvert % tableLen);
#else
  idx = (u_int)((u_int)vendorValue % tableLen);
#endif

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: getMacInfo(0x%02x%02x%02x) gives %ld (mod %d = %d)\n", 
                               ethAddress[0],
                               ethAddress[1],
                               ethAddress[2],
#ifdef PARM_USE_MACHASH_INVERT
                               vendorValueInvert,
#else
                               vendorValue,
#endif
                               tableLen,
                               idx);
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

    /* Count collisions during lookup - only ONCE per mac address */
    if (hasCollision == 0) {
        myGlobals.hashCollisionsLookup++;
        hasCollision=1;
#ifdef DEBUG
        traceEvent(CONST_TRACE_INFO, "DEBUG: Hash Collision - %d %x vs. %x\n", 
                                     idx, vendorValue, vendorTable[idx]->vendorId);
#endif
    }
  }
}

/* *********************************** */

char* getVendorInfo(u_char* ethAddress, short encodeString) {
  return(getMacInfo(vendorHash, ethAddress, MAX_VENDOR_NAME_HASH, encodeString));
}

/* *********************************** */

char* getSAPInfo(u_int16_t sapInfo, short encodeString) {
  u_int idx;
  unsigned long vendorValue = (unsigned long)sapInfo;
  VendorInfo* cursor;

  idx = (u_int)((u_int)sapInfo % MAX_IPXSAP_NAME_HASH);

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

    idx = (idx+1)%MAX_IPXSAP_NAME_HASH;
  }

  return(""); /* NOTREACHED */
}

/* *********************************** */

char* getSpecialMacInfo(HostTraffic* el, short encodeString) {
  datum key_data, data_data;
  static char tmpBuf[96];
  char* ret = getMacInfo(specialMacHash, el->ethAddress, 
			 MAX_SPECIALMAC_NAME_HASH, encodeString);

  if((ret != NULL) && (ret[0] != '\0'))
    return(ret); 

  /* Search the specified MAC address into 'ntop.db' */
  strncpy(tmpBuf, el->ethAddressString, sizeof(tmpBuf));
  key_data.dptr = tmpBuf;
  key_data.dsize = strlen(tmpBuf)+1;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Fetching '%s'\n", tmpBuf);
#endif

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.gdbmMutex, "getSpecialMacInfo");
#endif 

  data_data = gdbm_fetch(myGlobals.gdbm_file, key_data);

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
#endif 

  if(data_data.dptr != NULL) {    
    strncpy(tmpBuf, data_data.dptr, sizeof(tmpBuf));
    free(data_data.dptr);
    return(tmpBuf);
  } else
    return("");
}

/* *********************************** */

void createVendorTable(void) {
  int idx;

#ifdef TEST_HASHSIZE_SPECIAL
{
  int i, j, best, besti;

  traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: Testing specialMacHash (%s) from 51 -> %d...wait\n", 
#ifdef PARM_USE_MACHASH_INVERT
                               "invert",
#else
                               "normal",
#endif
                               MAX_SPECIALMAC_NAME_HASH);
  best=99999;
  besti=0;
  for (i=51; i<=MAX_SPECIALMAC_NAME_HASH; i += 2) {
      j=0;
      for(idx=0; specialMacInfo[idx].vendorName != NULL; idx++)
          j += addMacTableEntry(specialMacHash, &specialMacInfo[idx], i);
      if (j == 0) {
          best=0;
          besti=i;
          break;
      } else if ( j < best ) {
          best = j;
          besti = i;
          traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: specialMacHash %3d %3d\n", i, j);
      }
      memset(specialMacHash, 0, sizeof(specialMacHash));
  }
  traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: specialMacHash BEST is %d collisions, size %d\n", best, besti);
}
#endif

#ifdef TEST_HASHSIZE_IPXSAP
{
  int i, j, best, besti;

  traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: Testing ipxSAP (%s) from 51 -> %d...wait\n",
#ifdef PARM_USE_MACHASH_INVERT
                               "invert",
#else
                               "normal",
#endif
                                MAX_IPXSAP_NAME_HASH);
  best=99999;
  besti=0;
  for (i=51; i<=MAX_IPXSAP_NAME_HASH; i += 2) {
      j=0;
      for(idx=0; ipxSAP[idx].vendorName != NULL; idx++)
          j += addMacTableEntry(ipxSAPhash, &ipxSAP[idx], i);
      if (j == 0) {
          best=0;
          besti=i;
          break;
      } else if ( j < best ) {
          best = j;
          besti = i;
          traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: ipxSAP %3d %3d\n", i, j);
      }
      memset(ipxSAPhash, 0, sizeof(ipxSAPhash));
  }
  traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: ipxSAP BEST is %d collisions, size %d\n", best, besti);
}
#endif

#ifdef TEST_HASHSIZE_VENDOR
{
  int i, j, best, besti, minv;

  best=99999;
  besti=0;
  minv=0;
  for(idx=0; vendorInfo[idx].vendorName != NULL; idx++)
      minv++;
  minv = ((minv + 250) / 2) * 2 + 1;
  traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: Testing vendors (%s) from %d -> %d...wait\n",
#ifdef PARM_USE_MACHASH_INVERT
                               "invert",
#else
                               "normal",
#endif
                               minv, MAX_VENDOR_NAME_HASH);

  for (i=minv; i<=MAX_VENDOR_NAME_HASH; i += 2) {
      if ( (i-1) % 2500 == 0 ) traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: testing %5d\n", i);
      j=0;
      for(idx=0; vendorInfo[idx].vendorName != NULL; idx++)
          j += addMacTableEntry(vendorHash, &vendorInfo[idx], i);
      if (j == 0) {
          best=0;
          besti=i;
          break;
      } else if ( j < best ) {
          if ((j + 50 < best) || (j < 25) ) {
              traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: vendor %5d %5d\n", i, j);
          }
          best = j;
          besti = i;
      }
      memset(vendorHash, 0, sizeof(vendorHash));
  }
  traceEvent(CONST_TRACE_INFO, "TEST_HASHSIZE: vendors BEST is %d collisions, size %d\n", best, besti);
}
#endif

  for(idx=0; vendorInfo[idx].vendorName != NULL; idx++)
    myGlobals.vendorHashLoadCollisions += 
        addMacTableEntry(vendorHash, &vendorInfo[idx], MAX_VENDOR_NAME_HASH);

  for(idx=0; specialMacInfo[idx].vendorName != NULL; idx++)
    myGlobals.specialHashLoadCollisions += 
        addMacTableEntry(specialMacHash, &specialMacInfo[idx], MAX_SPECIALMAC_NAME_HASH);

  for(idx=0; ipxSAP[idx].vendorName != NULL; idx++)
    myGlobals.ipxsapHashLoadCollisions += 
        addMacTableEntry(ipxSAPhash, &ipxSAP[idx], MAX_IPXSAP_NAME_HASH);
}

