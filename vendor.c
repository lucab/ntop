/*
 *  Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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
 *   Vendor
 *       The official list is updated daily at http://standards.ieee.org/regauth/oui/oui.txt
 *       The vendor table data does change, frequently, albeit irrelevantly to most of us.
 *       The ntop version of oui.txt is updated infrequently.
 *
 *       To update (if say, you're seeing a lot of unknown values), download the list:
 *
 *           $ make dnvt
 *
 *       Warning: the mac address list frequently discussed on the 'net at
 *       http://www.cavebear.com/CaveBear/Ethernet/vendor.html hasn't been
 *       updated since 1999.
 *
 *       If you want to save (disk) space, an oui.txt customized with only the ones
 *       you really need is certainly possible.
 *
 *   Special MAC
 *       The special mac table is referenced - lookupHost() in hash.c calls
 *       getSpecialMacInfo() in util.c - each time a new (pseudo) local host
 *       is found.
 *
 *       I (Burton) am unaware of any official or even pseudo-offical list.
 *
 *       A 'special' MAC is one that's assigned (often in an RFC, IEEE standard,
 *       by consensus or in some other unusual way).  It doesn't represent a PHYSICAL
 *       device or manufacturer.
 *
 *       It's a mess...
 *
 *       For example, 0x0180C2-000000 through -00000f, are reserved in
 *       "ANSI/IEEE Standard 802.1D (1998 edition)".  See page 70 in
 *       http://standards.ieee.org/getieee802/download/802.1D-1998.pdf
 *
 *       For example, the 2nd bit of a MAC address denotes an LAA, a Locally Assigned
 *       Address value.  See IEEE 802.3-2002 (or earlier versions).
 *       Because bits are xmitted low to high , this stream, 0100000000000000...
 *       is MAC address 0x02000000.  (See RFC 1638)
 *
 *       These don't represent a manufacturer, but are values arbitrarily
 *       set by some network admin...
 *
 *       Also, see http://www.iana.org/assignments/ppp-numbers for CF0000xxxxxx
 */

/*
 * NOTE: About optimzing hash size...
 *
 *   See the #define TEST_HASHSIZE_xxxxxx's below.
 *
 *   Enabling it may run for a bit, as it tests each possible odd value from
 *   some low number up to whatever the MAX_ value is in globals-defines.h.
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
 */

#include "ntop.h"

// #define VENDOR_DEBUG

static char* macInputFiles[] = {
  "specialMAC.txt",
  "oui.txt",
  NULL
};

/* *********************************** */

static char* getMACInfo(int special, u_char* ethAddress, short encodeString) {
  datum key_data, data_data;
  static char tmpBuf[96];
  char *workBuf;
  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];

  workBuf = etheraddr_string(ethAddress, etherbuf);
  memcpy(&tmpBuf, workBuf, LEN_ETHERNET_ADDRESS_DISPLAY+1);
#ifdef VENDOR_DEBUG
  traceEvent(CONST_TRACE_INFO, "VENDOR_DEBUG: %slookup '%s'",
                               special == 1 ? "special " : "", tmpBuf);
#endif

  if(special == TRUE) {
      /* Search the database for the specified MAC address - full 48 bit */
      key_data.dptr = tmpBuf;
      key_data.dsize = (int)(strlen(tmpBuf)+1);

#ifdef VENDOR_DEBUG
      traceEvent(CONST_TRACE_INFO, "VENDOR_DEBUG: Fetching 48bit '%s'", tmpBuf);
#endif

      data_data = gdbm_fetch(myGlobals.macPrefixFile, key_data);
      
      if(data_data.dptr == NULL) {
	/* Maybe this is just the initial MAC (e.g 00:11:22) */
	if(key_data.dsize > 8) {
	  key_data.dptr[8] = '\0';
	  key_data.dsize   = 9;
	}
      }

      if((data_data.dptr != NULL) && (((MACInfo*)data_data.dptr)->isSpecial = 's')) {
	strncpy(tmpBuf, ((MACInfo*)data_data.dptr)->vendorName, sizeof(tmpBuf));
	free(data_data.dptr);
	myGlobals.numVendorLookupFound48bit++;
	return(tmpBuf);
      }
  }

  /* Try the 24 bit */

  tmpBuf[LEN_ETHERNET_VENDOR_DISPLAY-1] = '\0';   /* Mask off left 24 bits */
  key_data.dptr = tmpBuf;
  key_data.dsize = (int)(strlen(tmpBuf)+1);

#ifdef VENDOR_DEBUG
  traceEvent(CONST_TRACE_INFO, "VENDOR_DEBUG: Fetching 24bit '%s'", tmpBuf);
#endif

  data_data = gdbm_fetch(myGlobals.macPrefixFile, key_data);

  if(data_data.dptr != NULL) {
    if(((special == TRUE)  && (((MACInfo*)data_data.dptr)->isSpecial = 's')) ||
       ((special == FALSE) && (((MACInfo*)data_data.dptr)->isSpecial != 's'))) {
      strncpy(tmpBuf, ((MACInfo*)data_data.dptr)->vendorName, sizeof(tmpBuf));
      free(data_data.dptr);
      myGlobals.numVendorLookupFound24bit++;
      return(tmpBuf);
    }
  }


  /* Hand coded for LAA/Multicast */
  if(((ethAddress[5] & 0x01) == 0) && ((ethAddress[6] & 0x01) == 0)) {
    /*
      This is a dummy MAC that instead contains an IP addresses
      in the first four bytes

      Example: 0D:68:2B:C1:00:00
    */
    return("");
  }

 /* Hand coded for LAA/Multicast */
  if((ethAddress[0] & 0x01) != 0) {
    myGlobals.numVendorLookupFoundMulticast++;
    return("Multicast");
  }

  if((ethAddress[0] & 0x02) != 0) {
    myGlobals.numVendorLookupFoundLAA++;
    return("LAA (Locally assigned address)");
  }

  traceEvent(CONST_TRACE_NOISY, "MAC prefix '%s' not found in vendor database", tmpBuf);

  return("");
}

/* *********************************** */

char* getVendorInfo(u_char* ethAddress, short encodeString) {
  char* ret;

  if(memcmp(ethAddress, myGlobals.otherHostEntry->ethAddress, LEN_ETHERNET_ADDRESS) == 0)
    return("");

  ret = getMACInfo(1, ethAddress, encodeString);

  myGlobals.numVendorLookupCalls++;

  if((ret != NULL) && (ret[0] != '\0'))
    return(ret);
  else
    return("");
}

/* *********************************** */

char* getSpecialMacInfo(HostTraffic* el, short encodeString) {
  char* ret = getMACInfo(1, (u_char*)&(el->ethAddress), encodeString);
  myGlobals.numVendorLookupSpecialCalls++;

  if((ret != NULL) && (ret[0] != '\0'))
    return(ret);
  else
    return("");
}

/* *********************************** */

void createVendorTable(struct stat *dbStat) {
  int idx, numRead, numLoaded;
  FILE *fd = NULL;
  char tmpLine[LEN_GENERAL_WORK_BUFFER];
  char tmpMACkey[LEN_ETHERNET_ADDRESS_DISPLAY+1];
  char *tmpMAC, *tmpTag1, *tmpTag2, *tmpVendor, *strtokState;
  struct macInfo macInfoEntry;
  datum data_data, key_data;
  u_char compressedFormat;

  /*
   * Ok, so we've loaded the static table.
   * Now load the gdbm database for the real stuff
   *   (database was created and opened in initGdbm() in initialize.c)
   *
   *  Here's a sample entry from oui.txt:

   OUI                             Organization
   company_id                      Organization
   Address


   00-00-00   (hex)                XEROX CORPORATION
   000000     (base 16)            XEROX CORPORATION
   M/S 105-50C
   800 PHILLIPS ROAD
   WEBSTER NY 14580

   *  and from (our, specially created) special.txt:

   018024        (special 24)      Kalpana Etherswitch
   0180C2000000  (special 48)      Bridge Sp. Tree/OSI Route

   *  We use the (base 16) as our key and add similar values for special
   *  mac entries so we could co-mingled them.
   *
   *  Note that any line without the 2nd word of '(base' or '(special' is
   *  simply ignored - allows comments if you're careful.
   *
   */

  traceEvent(CONST_TRACE_INFO, "VENDOR: Loading MAC address table.");
  for(idx=0; macInputFiles[idx] != NULL; idx++) {
    fd=checkForInputFile("VENDOR",
                         "MAC address table",
                         macInputFiles[idx], 
                         dbStat,
                         &compressedFormat);
    if(fd != NULL) {
      numLoaded=0;
      numRead=0;
      while(readInputFile(fd,
                          "VENDOR", 
                          FALSE,
                          compressedFormat,
                          5000,
                          tmpLine, sizeof(tmpLine),
                          &numRead) == 0) {
	int len;

	myGlobals.numVendorLookupRead++;
	if( (strstr(tmpLine, "(base") == NULL) &&
	    (strstr(tmpLine, "(special") == NULL) ) {
	  continue;
	}

#ifdef VENDOR_DEBUG
	traceEvent(CONST_TRACE_INFO, "VENDOR_DEBUG: Parsing '%s'", tmpLine);
#endif

	tmpMAC = strtok_r(tmpLine, " \t", &strtokState);
	if(tmpMAC == NULL) continue;
	tmpTag1 = strtok_r(NULL, " \t", &strtokState);
	if(tmpTag1 == NULL) continue;
	if((strcmp(tmpTag1, "(base") == 0) || (strcmp(tmpTag1, "(special") == 0)) {
	  tmpTag2 = strtok_r(NULL, " \t", &strtokState);
	  if(tmpTag2 == NULL) continue;
	  tmpVendor = strtok_r(NULL, "\n", &strtokState);
	  if(tmpVendor == NULL) continue;
	  /* Skip leading blanks and tabs*/

	  while ( (tmpVendor[0] == ' ') || (tmpVendor[0] == '\t') ) tmpVendor++;
	  memset(&macInfoEntry, 0, sizeof(macInfoEntry));
	  if(strcmp(tmpTag1, "(special") == 0) {
	    macInfoEntry.isSpecial = 's';
	  } else {
	    macInfoEntry.isSpecial = 'r';
	  }

	  if(strlen(tmpVendor) >= (MAX_LEN_VENDOR_NAME-1))
	    tmpVendor[MAX_LEN_VENDOR_NAME-1] = '\0';

	  strcpy(macInfoEntry.vendorName, tmpVendor);
	  data_data.dptr = (void*)(&macInfoEntry);
	  data_data.dsize = sizeof(macInfoEntry);
	  memset(tmpMACkey, 0, sizeof(tmpMACkey));
	  strncat(tmpMACkey, tmpMAC, 2); len = 2; tmpMACkey[len] = '\0';
	  strcat(tmpMACkey, ":"); len++; tmpMACkey[len] = '\0';
	  strncat(tmpMACkey, &tmpMAC[2], 2); len += 2; tmpMACkey[len] = '\0';
	  strcat(tmpMACkey, ":"); len++; tmpMACkey[len] = '\0';
	  strncat(tmpMACkey, &tmpMAC[4], 2); len += 2; tmpMACkey[len] = '\0';
	  if(strcmp(tmpTag2, "48)") == 0) {
	    /* special 48 - full tag */
	    strcat(tmpMACkey, ":"); len++; tmpMACkey[len] = '\0';
	    strncat(tmpMACkey, &tmpMAC[6], 2); len +=2; tmpMACkey[len] = '\0';
	    strcat(tmpMACkey, ":"); len++; tmpMACkey[len] = '\0';
	    strncat(tmpMACkey, &tmpMAC[8], 2); len +=2; tmpMACkey[len] = '\0';
	    strcat(tmpMACkey, ":");len++; tmpMACkey[len] = '\0';
	    strncat(tmpMACkey, &tmpMAC[10], 2); len +=2; tmpMACkey[len] = '\0';
	  }
	  key_data.dptr = tmpMACkey;
	  key_data.dsize = (int)(strlen(tmpMACkey)+1);
	  if(gdbm_store(myGlobals.macPrefixFile, key_data, data_data, GDBM_REPLACE) != 0) {
	    traceEvent(CONST_TRACE_WARNING,
		       "VENDOR: unable to add record '%s': {%d, %s} - skipped",
		       tmpMACkey, macInfoEntry.isSpecial, macInfoEntry.vendorName);
	  } else {
	    numLoaded++;
	    myGlobals.numVendorLookupAdded++;

#ifdef VENDOR_DEBUG
	    traceEvent(CONST_TRACE_INFO, "VENDOR_DEBUG: Adding '%s':'%s'", key_data.dptr, macInfoEntry.vendorName);
#endif

	    if(macInfoEntry.isSpecial == 's')
	      myGlobals.numVendorLookupAddedSpecial++;
#ifdef VENDOR_DEBUG
	    traceEvent(CONST_TRACE_INFO, "VENDOR_DEBUG: Added '%s': {%c, %s}",
		       tmpMACkey, macInfoEntry.isSpecial, macInfoEntry.vendorName);
#endif
	  }
	}
      } /* while ! eof */

      traceEvent(CONST_TRACE_INFO, "VENDOR: ...loaded %d records", numLoaded);
    } else {
      traceEvent(CONST_TRACE_INFO, 
                 "VENDOR: ntop continues ok");
    }

  } /* for macInputFiles */

    traceEvent(CONST_TRACE_INFO, "Fingerprint: Loading signature file");
      
    fd = checkForInputFile("Fingerprint", "Fingerprint file...",
			   CONST_OSFINGERPRINT_FILE, NULL, &compressedFormat);

    if(fd != NULL) {
      char line[384], lineKey[8];
      int numEntries=0;
          
      numLoaded = 0;
          
      while(readInputFile(fd, NULL, FALSE, compressedFormat, 0, line, sizeof(line), &numLoaded) == 0) {
	if((line[0] == '\0') || (line[0] == '#') || (strlen(line) < 30)) continue;
	line[strlen(line)-1] = '\0';
              
	safe_snprintf(__FILE__, __LINE__, lineKey, sizeof(lineKey), "%d", numEntries++);
	memset(&key_data, 0, sizeof(key_data));
	key_data.dptr = lineKey; key_data.dsize = (int)(strlen(key_data.dptr));
              
	memset(&data_data, 0, sizeof(data_data));
	data_data.dptr = line; data_data.dsize = (int)(strlen(line));
              
	if(gdbm_store(myGlobals.fingerprintFile, key_data, data_data, GDBM_REPLACE) != 0)
	  traceEvent(CONST_TRACE_ERROR, "While adding %s=%s.", lineKey, line);       
      }
          
      traceEvent(CONST_TRACE_INFO, "Fingerprint: ...loaded %d records", numEntries);
    } else
      traceEvent(CONST_TRACE_NOISY, "Unable to find fingeprint signature file.");  
}

