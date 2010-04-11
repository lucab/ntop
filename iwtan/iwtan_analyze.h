/* IWTAN analyze functions and data structures header.*/

/*
  Copyright (C) 2008 Marco Cornolti 
  
  IWTAN (IWTAN: Wireless Topology ANalyzer) is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3, or (at your option) any later version.
  
  IWTAN is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with IWTAN; see the file COPYING. If not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. 
*/


#ifndef _IWTAN_ANALYZE_H
#define _IWTAN_ANALYZE_H 1

#include <inttypes.h>
#include <pcap.h>
#include "iwtan_data.h"

#define IWTAN_BEACON_HDR_LEN 24 //size of a 802.11 frame header for a beacon frame.
#define IWTAN_DATA_HDR_LEN 24 //size of a 802.11 frame header for a data frame.

/* IEEE 802.11 radiotap header */
typedef struct {
  uint8_t revision;
  uint8_t pad0;
  uint16_t length; //little endian
  uint8_t pad1[4];
  uint8_t timestamp[8];
  uint8_t flags;
  uint8_t dataRate;
  uint16_t frequency; //little endian
  uint16_t type; //little endian
  uint8_t antenna;
  uint8_t signal;
} radiotap_header;

/* IEEE 802.11 frame header */
typedef struct {
  uint16_t control; //little endian
  uint16_t duration; //little endian
  uint8_t mac1[6];
  uint8_t mac2[6];
  uint8_t mac3[6];
  uint16_t SeqCtl; //little endian
  uint8_t mac4[6];
  uint16_t gapLen; //little endian
  uint8_t gap[8];
} ieee_802_11_header;

/* IPv6 header */
typedef struct {
  uint8_t firstByte;
  uint8_t pad0[3];
  uint16_t payloadLen; //big endian
  uint8_t nextHeader;
  uint8_t hop;
  uint8_t source[16];
  uint8_t destination[16];
  //here begins the payload.
} ip6_hdr;

/* IPv4 header */
typedef struct {
  uint8_t version;
  uint8_t services;
  uint16_t length; //big endian
  uint16_t identification; //big endian
  uint16_t flags; //big endian
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum; //big endian
  uint8_t source[4];
  uint8_t destination[4];
} ip4_hdr;

// Structure of a IEEE 802.11 management frame: it starts with a ieee_802_11_mng_fixed_begin and in the middle contains 0 or more variable-length tags (ieee_802_11_mng_tag) describing the AP properties. Ends with ieee_802_11_mng_fixed_end.
typedef struct {
  uint8_t fixedParameters[12];
  //here begin the tags
} ieee_802_11_mng_fixed_begin;

typedef struct {
  uint8_t tagNumber; //type of tag (0x0:essid string, 0x1: supported rates, 0x3: DS parameter set)
  uint8_t tagLen; //tag lenght
  //here begins the tag of lenght tagLenght
} ieee_802_11_mng_tag;

typedef struct {
  uint8_t crc[4];
} ieee_802_11_mng_fixed_end;


/* A 802 Link Layer Control header */
typedef struct {
  uint8_t pad[6]; //may be sub-typed if needed
  uint16_t type; //big endian
} ieee_802_11_llc;

/* An ethernet header */
typedef struct {
  uint8_t destination[6]; //destination mac address
  uint8_t source[6]; //source mac address
  uint16_t type; //type of packet, big endian
} ethernet_hdr;

/* ++++++++++++++++++++++++++++++ Functions +++++++++++++++++++++++++++++++++ */

/* Main analyzing functions */
int iwtan_refresh_data(unsigned int length, const u_char* pktBody, int packetType, iwtan_context* context);

/* Internal datalink type processing and validating functions */
int _iwtan_process_radiotap(const u_char* radiotapData, unsigned int radioTapSize, short* WEPped, unsigned int* dataRate, short* antenna, unsigned int* frequency, short* type, short* signal, mac_address** stMac, mac_address** apMac, mac_address** bssId, char** essid, ip4_address* stIp4, ip6_address* stIp6);
int _iwtan_validate_radiotap(const u_char* body, bpf_uint32 len);
int _iwtan_process_802_11(const u_char* body, bpf_uint32 len, mac_address** ap_mac, mac_address** st_mac, mac_address** bssId, char** essid, ip4_address* stationIP4, ip6_address* stationIP6);
int _iwtan_process_802_11_mng(const u_char* body, bpf_uint32 len, char** essid);
int _iwtan_process_802_llc(const u_char* body, bpf_uint32 len, ip4_address* fromIp4, ip4_address* toIp4, ip6_address* fromIp6, ip4_address* toIp6);
int _iwtan_process_ip4(const u_char* body, bpf_uint32 len, ip4_address* fromIp4, ip4_address* toIp4);
int _iwtan_process_ip6(const u_char* body, bpf_uint32 len, ip6_address* fromIp6, ip6_address* toIp6);

/* Internal utility functions (bits) */
uint16_t _iwtan_le_to_host(uint16_t leData);
uint16_t _iwtan_be_to_host(uint16_t beData);
short _iwtan_byte_to_bool(u_char byte, short position);

/* Internal utility functions (nets) */
int _iwtan_ip4_is_broadcast(ip4_address ip4);
int _iwtan_ip6_is_broadcast(ip6_address ip6);
int _iwtan_mac_is_broadcast(mac_address* mac);

#endif
