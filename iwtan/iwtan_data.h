/* IWTAN context process and browse functions header.*/

/*
  Copyright (C) 2008 Marco Cornolti 
  
  IWTAN (IWTAN: Wireless Topology ANalyzer) is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3, or (at your option) any later version.
  
  IWTAN is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with IWTAN; see the file COPYING. If not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. 
*/

#ifndef _IWTAN_DATA_H
#define _IWTAN_DATA_H 1

#include <pthread.h>
#include <inttypes.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <time.h>

/* addresses lenght */
#define IWTAN_MAC_LEN 6 //number of bytes of a MAC address (both ethernet and 802.11)
#define IWTAN_IP4_LEN 4 //number of bytes of a IPv4 address
#define IWTAN_IP6_LEN 16 //number of bytes of a IPv6 address

/* address format definitions */
typedef struct ether_addr mac_address;
typedef uint8_t* ip4_address;
typedef uint8_t* ip6_address;


/* representation of an access point */
typedef struct { // when you edit this structure, also edit _iwtan_copy_AP()
  
  //datas obtainted by the radiotap header
  short WEPped; // 1<==>wep is on
  unsigned int dataRate; // datarate in Mb/s
  unsigned short antenna; //antenna ID
  unsigned int frequency; //channel frequency
  short type; //0:unknown, 1: 802.11b
  short signal; //signal strenght in decibel
  
  //data obtained by the beacon frame
  mac_address* bssId;

  //data obtained by the wlan management frame
  char* essid;

  //data set by user/program
  char* description;
  unsigned int associations; //number of associated stations
  time_t lastSeen;

} iwtan_ap;

/* representatione of a wireless station */
typedef struct { // when you edit this structure, also edit _iwtan_copy_station()
  ip4_address ip4;
  mac_address* mac;
  ip6_address ip6;
  time_t lastSeen;
} iwtan_station;

/* an element of a list containing wi_stations*/
typedef struct _wi_ll_station_el{
  iwtan_station* station;
  struct _wi_ll_station_el* next;
} iwtan_station_el;

/* an element of a list containing wi_ap's*/
typedef struct _wi_ll_ap_el{
  iwtan_ap* ap;
  struct _wi_ll_ap_el* next;
} iwtan_ap_el;

/* an association between a wireless station and an AP */
typedef struct {
  iwtan_station* station;
  iwtan_ap* ap;
} iwtan_association;

/* IWTAN operating context */
typedef struct{
  pthread_mutex_t mutex; //mutex to avoid data access conflicts
  unsigned int assN; //number of contained associations
  unsigned int allAss; //number of allocated associations
  iwtan_association* ap_ass; //associations ordered by AP mac address
  iwtan_association* st_ass; //associations ordered by station mac address
  unsigned int apN; //number of access points in the list
  unsigned int allAP; //number of allocated positions in the access points list
  iwtan_ap** ap_list; //list of access points ordered by BSS Id
} iwtan_context;

/* ++++++++++++++++++++++++++++++ Functions +++++++++++++++++++++++++++++++++ */

/* Data context functions */
int iwtan_context_initialize(iwtan_context* context);
int iwtan_context_destroy(iwtan_context* context);

/* Data browsing functions */
iwtan_station_el* iwtan_get_by_AP(mac_address* bssId, iwtan_context* context);
iwtan_ap* iwtan_get_by_station(mac_address* stMac, iwtan_context* context);
iwtan_station_el* iwtan_get_all_stations(iwtan_context* context);
iwtan_ap_el* iwtan_get_all_APs(iwtan_context* context);
iwtan_association* iwtan_get_all_associations(iwtan_context* context, unsigned int* elementsN);
iwtan_ap* iwtan_get_by_essid(char* essid, iwtan_context* context);

/* Utility functions*/
int iwtan_free_stations_ll(iwtan_station_el* freeEl);
int iwtan_free_AP_ll(iwtan_ap_el* freeEl);
int iwtan_free_ass_array(iwtan_association* ass, int size);
int iwtan_free_AP(iwtan_ap* ap);
int iwtan_free_station(iwtan_station* station);
int iwtan_cmp_mac(mac_address* mac1, mac_address* mac2);
char* iwtan_ip4toa(ip4_address ip4, char* result);
char* iwtan_ip6toa(ip6_address ip6, char* result);

/* Internal Data editing functions */
int _iwtan_add_association(mac_address* bssId, mac_address* station_mac, iwtan_context* context);
int _iwtan_remove_AP (iwtan_ap* ap, iwtan_context* context);
iwtan_ap* _iwtan_add_new_AP(mac_address* bssId, iwtan_context* context);
int _iwtan_add_new_association(iwtan_station* station, iwtan_ap* ap, iwtan_context* context);
int _iwtan_update_AP (iwtan_ap* ap, short wepped, unsigned int dataRate, unsigned short antenna, unsigned int frequency, short type, short signal, mac_address* bssId, char* essid, char* description, time_t lastSeen);
int _iwtan_update_station (iwtan_station* st, ip4_address ip4, mac_address* mac, ip6_address ip6, time_t lastSeen);

/* Internal Utility functions */
int  _iwtan_bsearch_by_station(mac_address* st_mac, iwtan_context* con);
iwtan_station*  _iwtan_bsearch_station(mac_address* st_mac, iwtan_context* con);
iwtan_ap** _iwtan_bsearch_AP(mac_address* bssId, iwtan_context* context);

int _iwtan_first_bsearch_by_AP(mac_address* bssId, iwtan_context* con);

int _iwtan_init_AP(mac_address* bssId, iwtan_ap* ap);
int _iwtan_init_station(mac_address* st_mac, iwtan_station* station);

int _iwtan_cmp_assoc_by_AP(const iwtan_association* ass1, const iwtan_association* ass2);
int _iwtan_cmp_assoc_by_station(const iwtan_association* ass1, const iwtan_association* ass2);
int _iwtan_cmp_AP(const iwtan_ap** ap1_ref, const iwtan_ap** ap2_ref);

iwtan_station* _iwtan_copy_station (iwtan_station* st);
iwtan_ap* _iwtan_copy_AP (iwtan_ap* ap);
ip4_address _iwtan_copy_ip4(ip4_address ip4);
ip6_address _iwtan_copy_ip6(ip6_address ip6);
mac_address* _iwtan_copy_mac(mac_address* mac);
mac_address* _iwtan_copy_mac_by_array(uint8_t* array);

#endif
