/* IWTAN analyze functions and data structures.*/

/*
  Copyright (C) 2008 Marco Cornolti 
  
  IWTAN (IWTAN: Wireless Topology ANalyzer) is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3, or (at your option) any later version.
  
  IWTAN is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with IWTAN; see the file COPYING. If not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. 
*/

#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>
#include <sys/types.h>
#include <pthread.h>
#include <math.h>
#include <asm/byteorder.h>
#include <string.h>

#include "iwtan_analyze.h"
#include "iwtan_data.h"

/*
  Refresh the data structure extracting the information by a packet passed by argument. 
  length is the length of the packet in bytes.
  pktBody is a pointer to the packet body.
  packetType is the packet type as defined by pcap.h (DTL_*)
  Returns 0 in case of no errors. Returns 1 if the packet type could not be recognized. 
*/
int iwtan_refresh_data(unsigned int length, const u_char* pktBody, int packetType, iwtan_context* context){
  pthread_mutex_lock(&(context->mutex));

  int retVal=0;
  
  //all the data that may be obtained for an access point by the radiotap header, initialized to null values.
  short WEPped = -1;
  unsigned int dataRate = 0;
  unsigned short antenna = 0;
  unsigned int frequency = 0;
  short type = 0;
  short signal = 0;

  //data obtained by the 802.11 frame
  mac_address* stMac = NULL;
  mac_address* apMac = NULL;
  mac_address* bssId = NULL;
  
  //data obtained by the wlan management frame
  char* essid = NULL;

  //data obtained by the IP level
  ip4_address stIp4 = NULL;
  ip6_address stIp6 = NULL;

  //data obtained by an ethernet-emulated packet
  mac_address* srcMac = NULL;
  mac_address* destMac = NULL;
  ip4_address srcIp4 = NULL;
  ip6_address srcIp6 = NULL;
  ip4_address destIp4 = NULL;
  ip6_address destIp6 = NULL;
  

  //determine what's the kind of the analyzed packet and call the right processing function.
  switch (packetType){
  case DLT_IEEE802_11_RADIO: 
    if (_iwtan_validate_radiotap(pktBody, length)){
      _iwtan_process_radiotap(pktBody, length, &WEPped, &dataRate, &antenna, &frequency, &type, &signal, &stMac, &apMac, &bssId, &essid, &stIp4, &stIp6);
    }
    break;
  case DLT_IEEE802_11:
    _iwtan_process_802_11(pktBody, length, &apMac, &stMac, &bssId, &essid, &stIp4, &stIp6);
    break;
  case DLT_EN10MB:
    _iwtan_process_ethernet(pktBody, length, &srcMac, &destMac, &srcIp4, &srcIp6, &destIp4, &destIp6);
    //If we are analyzing an ethernet packet, we know what is the source and the destination, but we don't know witch one is the station and witch one is the AP. So, if we find the source mac address in the list of known access points, then we know that the IP destination is a station, if we find the destination MAC address in the list of known APs then we know that the source is a station, but if we can't find the destination mac nor the source mac in the list, we can't tell where the packet comes from.

    if (_iwtan_bsearch_AP(srcMac, context)){
	apMac = srcMac;
	stMac = destMac;
	stIp4 = destIp4;
	stIp6 = destIp6;
	free(srcIp4);
	free(srcIp6);	
      }
    else if (_iwtan_bsearch_AP(destMac, context)){
	apMac = destMac;
	stMac = srcMac;
	stIp4 = srcIp4;
	stIp6 = srcIp6;
	free(destIp4);
	free(destIp6);	
    }
    else{
      free(destMac);
      free(srcMac);
      free(srcIp4);
      free(srcIp6);
      free(destIp4);
      free(destIp6);
    }

    break;
  default:
    retVal = 1;
  }

  //pick the right ap to create it or update its data. An ap may exist without any associated station.
  if (apMac){
    iwtan_ap** apRef = _iwtan_bsearch_AP(apMac, context);
    iwtan_ap* ap;
    if (!apRef)
      ap = _iwtan_add_new_AP(apMac, context);
    else
      ap = *apRef;

    _iwtan_update_AP (ap, WEPped, dataRate, antenna, frequency, type, signal,  apMac, bssId, essid, NULL, time(NULL));

    //if an AP and a station has been seen, create an association.
    if (stMac){
      _iwtan_add_association(apMac, stMac, context);

      //pick the right station and update its data.
      iwtan_station* sta = _iwtan_bsearch_station(stMac, context);
      _iwtan_update_station (sta, stIp4, stMac, stIp6, time(NULL));
    }
  } 
  else{ //no AP were found (e.g. a station sent a multicast packet)
    if (stMac){ //pick the right station, if present, and update its data.
      iwtan_station* sta = _iwtan_bsearch_station(stMac, context);
      if (sta) _iwtan_update_station (sta, stIp4, stMac, stIp6, time(NULL));
      else {      //otherwise, we don't create stations that aren't associated to an ap, and we just free the obtained addresses.
	free(stMac);
	free(stIp4);
	free(stIp6);
      }
    }
    free(bssId); //in any case, bssId is not useful.

  }

  pthread_mutex_unlock(&(context->mutex));

  return retVal;
}


/*
  Process a radiotap header pointed by packetData.
  Stores the radiotap header size (just the header) in radioTapSize, writes wether or not the signal has a wep encription in WEPped, the dataRate in Mbps in dataRate, the antenna ID in antenna, the channel frequency in frequency, the signal type in type.
  Returns 1 in case of error, e.g. for broken packages.
*/
int _iwtan_process_radiotap(const u_char* radiotapData, unsigned int radioTapSize, short* WEPped, unsigned int* dataRate, short* antenna, unsigned int* frequency, short* type, short* signal, mac_address** stMac, mac_address** apMac, mac_address** bssId, char** essid, ip4_address* stIp4, ip6_address* stIp6){
  radiotap_header* rt =  (radiotap_header*) radiotapData; 
  *WEPped = _iwtan_byte_to_bool(rt->flags,5);
  *dataRate = rt->dataRate * 2;
  *antenna = rt->antenna;
  *frequency = _iwtan_le_to_host(rt->frequency);
  switch(_iwtan_le_to_host(rt->type)){
  case 0x00a0:
    *type = 1;
    break;
  default: 0; break;
  }
  *signal = rt->signal;

  //radiotap packets contain 802.11 packets.
  _iwtan_process_802_11(radiotapData+_iwtan_le_to_host(rt->length), radioTapSize -( _iwtan_le_to_host(rt->length) + 4), apMac, stMac, bssId, essid, stIp4, stIp6);

}

/*
  Validate a 802.11 radiotap packet pointed by body of length len, checking its CRC.
  Returns 1 if the packet is a valid radiotap header or 0 otherwise. 
*/
int _iwtan_validate_radiotap(const u_char* body, bpf_u_int32 len){
  //  ieee_802_11_header* pkt (ieee_802_11_header*) ;
  //TODO:implement
  return 1;
}

/*
  Process a 802.11 packet extracting all its data.
  Set ap_mac to the MAC address of the access point sending the packet or NULL if no access points are meant.
  Set st_mac to the MAC address of the station if the packet has a single (not broadcast) destination, NULL otherwise.
  Set bssId to the BSS id.
  Set essid to the ESSID of the access point if the packet is a beacon frame, tu NULL otherwise.
  Set stationIP4 to the station IP4 address if the frame contained an IPv4 packet with a single destination (not broadcast).
  Set stationIP6 to the station IP6 address if the frame contained an IPv6 packet with a single destination (not broadcast).
  All the extracted data is allocated separetly and should be freed when no longer needed.
*/
int _iwtan_process_802_11(const u_char* body, bpf_u_int32 len, mac_address** ap_mac, mac_address** st_mac, mac_address** bssId, char** essid, ip4_address* stationIP4, ip6_address* stationIP6){
  ieee_802_11_header* frm = (ieee_802_11_header*) body;
  switch (_iwtan_le_to_host(frm->control)){
  case 0x0208: //Frame contains data from a DS to a station via an access point. This means that MAC 1 is the destination (station) address, MAC2 is the BSS id, MAC3 is the source (AP) address
  case 0x0A08:
    if (_iwtan_mac_is_broadcast((mac_address*)frm->mac1)){ //Multicast and broadcast transmissions from stations are codified as frames from DS to Station. They have a multicast/bradcast destination (MAC 1), the MAC address 3 is the station address (instead of the AP's), and the BSS id is regular (MAC 2).
      *ap_mac = NULL;
      *bssId = _iwtan_copy_mac_by_array(frm->mac2);
      *st_mac = _iwtan_copy_mac_by_array(frm->mac3);
    }
    else {
      *st_mac = _iwtan_copy_mac_by_array(frm->mac1);
      *bssId = _iwtan_copy_mac_by_array(frm->mac2);
      *ap_mac = _iwtan_copy_mac_by_array(frm->mac3);
  }
  _iwtan_process_802_llc(body + IWTAN_DATA_HDR_LEN, len-IWTAN_DATA_HDR_LEN, NULL, stationIP4, NULL, stationIP6);
    break;

  case 0x0108: //Frame contains data from a Station to a DS via an access point. This means that MAC1 is the BSS id, MAC2 is the source (station) address, MAC3 is the destination (AP) address.
    *bssId = _iwtan_copy_mac_by_array(frm->mac1);
    *st_mac = _iwtan_copy_mac_by_array(frm->mac2);
    *ap_mac = _iwtan_mac_is_broadcast((mac_address*)frm->mac3) ? NULL : _iwtan_copy_mac_by_array(frm->mac3);
    _iwtan_process_802_llc(body + IWTAN_DATA_HDR_LEN, len-IWTAN_DATA_HDR_LEN, stationIP4, NULL, stationIP6, NULL);
    break;

  case 0x0080: //Frame is a beacon frame (contains a wlan management frame)
    *ap_mac = _iwtan_copy_mac_by_array(frm->mac2);
    *bssId = _iwtan_copy_mac_by_array(frm->mac3);
    _iwtan_process_802_11_mng(body + IWTAN_BEACON_HDR_LEN, len - IWTAN_BEACON_HDR_LEN - sizeof(ieee_802_11_mng_fixed_end), essid);
    break;
  }
}

/*
  Process a 802.11 management frame, extracting the ESSID.
  The ESSID is allocated as a string whose pointer is stored in *essid.
*/
int _iwtan_process_802_11_mng(const u_char* body, bpf_u_int32 len, char** essid){
  ieee_802_11_mng_fixed_begin* begin = (ieee_802_11_mng_fixed_begin*) body;
  ieee_802_11_mng_tag* tag;
  u_char* tagByte = (u_char*)(body + sizeof(ieee_802_11_mng_fixed_begin));

  while(tagByte < body+len){
    tag = (ieee_802_11_mng_tag*) tagByte;
    switch (tag->tagNumber){
    case(0x0)://tag contains an ESSID
      *essid = calloc(tag->tagLen+1, sizeof(char));
      strncpy(*essid, tagByte+2, tag->tagLen);
      break;
    }
    tagByte += 2 + tag->tagLen;
  }
}

/*
  Process a Link Layer Control header. If an IP packet is found, the source and destination IP addresses are stored in the pointers given by argument.
  The addresses are allocated in the heap and should be freed when no longer needed.
  The addresses are stored in the pointers given by argument only if their value is not NULL.
*/
int _iwtan_process_802_llc(const u_char* body, bpf_u_int32 len, ip4_address* fromIp4, ip4_address* toIp4, ip6_address* fromIp6, ip4_address* toIp6){
  ieee_802_11_llc* llc = (ieee_802_11_llc*) body;
  switch (_iwtan_be_to_host(llc->type)){
  case 0x0800: //llc contains an IPv4 packet
    _iwtan_process_ip4(body + sizeof(ieee_802_11_llc), len-sizeof(ieee_802_11_llc), fromIp4, toIp4);
    break;
  case 0x86dd: //llc contains an IPv6 packet
    _iwtan_process_ip6(body + sizeof(ieee_802_11_llc), len-sizeof(ieee_802_11_llc), fromIp6, toIp6);
    break;
  }
  return 0;
}

/*
  Process an ethernet header. If an IP packet is found, the source and destination IP addresses are stored in the pointers given by argument.
  The addresses are allocated in the heap and should be freed when no longer needed.
  The addresses are stored in the pointers given by argument only if their value is not NULL.
*/
int _iwtan_process_ethernet(const u_char* body, bpf_u_int32 len, mac_address** sourceMac, mac_address** destMac, ip4_address* srcIp4, ip6_address* srcIp6, ip4_address* destIp4, ip6_address* destIp6){
  ethernet_hdr* eth = (ethernet_hdr*) body;
  *sourceMac =  _iwtan_mac_is_broadcast((mac_address*)eth->source)? NULL : _iwtan_copy_mac_by_array(eth->source);
  *destMac =  _iwtan_mac_is_broadcast((mac_address*)eth->destination)? NULL : _iwtan_copy_mac_by_array(eth->destination);
  switch (_iwtan_be_to_host(eth->type)){
  case 0x0800: //ethernet contains an IPv4 packet
    _iwtan_process_ip4(body + sizeof(ethernet_hdr), len-sizeof(ethernet_hdr), srcIp4, destIp4);
    break;
  case 0x86dd: //llc contains an IPv6 packet
    _iwtan_process_ip6(body + sizeof(ethernet_hdr), len-sizeof(ethernet_hdr), srcIp6, destIp6);
    break;
  }
  return 0;
  

}


/*
  Process an IPv4 packet. The source and destination IP addresses are stored in the pointers given by argument.
  The addresses are allocated in the heap and should be freed when no longer needed.
  The addresses are stored in the pointers given by argument only if their value is not NULL.
*/
int _iwtan_process_ip4(const u_char* body, bpf_u_int32 len, ip4_address* fromIp4, ip4_address* toIp4){
  ip4_hdr* ip = (ip4_hdr*) body;
  switch (ip->version){
  case 0x45: //version: IPv4, header length:20
    if (fromIp4)
      *fromIp4 = _iwtan_ip4_is_broadcast(ip->source) ? NULL : _iwtan_copy_ip4(ip->source);
    if (toIp4)
      *toIp4 = _iwtan_ip4_is_broadcast(ip->destination) ? NULL : _iwtan_copy_ip4(ip->destination);
    break;
    //other version of IP?
  }
  return 0;
}

/*
  Process an IPv6 packet pointed by body of the size len.
  Writes (a pointer to) the source and destination addresses in the given addresses pointers, if they are not NULL.
  A value of NULL is stored in these pointers if the addresses are broadcasts.
*/
int _iwtan_process_ip6(const u_char* body, bpf_u_int32 len, ip6_address* fromIp6, ip6_address* toIp6){
  ip6_hdr* ip = (ip6_hdr*) body;
  switch (ip->firstByte / 0x10){
  case 0x6: //version: IPv6
    if (fromIp6)
      *fromIp6 = _iwtan_ip6_is_broadcast(ip->source) ? NULL : _iwtan_copy_ip6(ip->source);
    if (toIp6) 
      *toIp6 = _iwtan_ip6_is_broadcast(ip->destination) ? NULL : _iwtan_copy_ip6(ip->destination);
    break;
  }
  return 0;
}


/*
  Given a byte, returns the value of the Nth bit in the byte (beginning from zero at left), returns -1 on errors.
*/
short _iwtan_byte_to_bool(u_char byte, short position){
  if (position >=8 || position<0) return -1;
  position = 7-position;
  return (byte % (short)pow(2, position + 1)) / (short)pow(2, position);
}

/*
  Convert a 16-bit value from little endian notation to host notation.
*/
uint16_t _iwtan_le_to_host(uint16_t leData){
#if defined(__LITTLE_ENDIAN_BITFIELD)
  return leData;
#elif defined (__BIG_ENDIAN_BITFIELD)
  return (leData%256)*256+leData/256;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
}

/*
  Convert a 16-bit value from little endian notation to host notation.
*/
uint16_t _iwtan_be_to_host(uint16_t beData){
#if defined(__LITTLE_ENDIAN_BITFIELD)
  return (beData%256)*256+beData/256;
#elif defined (__BIG_ENDIAN_BITFIELD)
  return beData;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
}

/* Returns 1 if and only if the IPv4 address pointed by ip4 is a broadcast address.*/
int _iwtan_ip4_is_broadcast(ip4_address ip4){
  int i=3;
  uint8_t* bytei=ip4+i;
  do{
    if (*bytei == 0xff) return 1;
    bytei--;
    i--;
  } while (i>=0);
  return 0;    
}

/* Returns !=0 if and only if the IPv6 address pointed by ip6 does not have a single destination (i.e. is multicast).*/
int _iwtan_ip6_is_broadcast(ip6_address ip6){
  return (*ip6 == 0xff && *(ip6+1) == 0x00);
}

/*
  Returns !=0 if and only if the MAC address pointed by mac is not a single destination (broadcast or multicast).
*/
int _iwtan_mac_is_broadcast(mac_address* mac){
  if (mac->ether_addr_octet[0] == 0x01 &&
      mac->ether_addr_octet[1] == 0x00) return 1; //multicast destination
  int i=0;
  while (i<6){
    if (mac->ether_addr_octet[i] != 0xff) return 0;
    i++;
  }
  return 1;
}
