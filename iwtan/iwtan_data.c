/* IWTAN context process and browse functions.*/

/*
  Copyright (C) 2008 Marco Cornolti 
  
  IWTAN (IWTAN: Wireless Topology ANalyzer) is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3, or (at your option) any later version.
  
  IWTAN is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License along with IWTAN; see the file COPYING. If not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. 
*/


#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <time.h>
#include <string.h>

#include "iwtan_data.h"

/* ++++++++++++++ Data refreshing  +++++++++++++++++++ */

/*
  Initialize a clear IWTAN context. Returns 0 on success or !=0 on error.
*/
int iwtan_context_initialize(iwtan_context* context){
  if (pthread_mutex_init(&(context->mutex), NULL)) return -1;
  if (context==NULL) return -1;
  context->allAss = 10;
  context->assN = 0;
  context->ap_ass = calloc(context->allAss, sizeof(iwtan_association));
  context->st_ass = calloc(context->allAss, sizeof(iwtan_association));
  context->apN=0;
  context->allAP=2;
  context->ap_list = calloc(context->allAP, sizeof(iwtan_ap*));
  return 0;
}

/*
  Destroy an IWTAN context. No other threads should use the context when this method is called. Returns 0 on success or !=0 on failure.
*/
int iwtan_context_destroy(iwtan_context* context){
  if (pthread_mutex_lock(&(context->mutex))) return -1;
  int i;
  /*Free all stations*/
  for (i=0;i<context->assN;i++)
    iwtan_free_station(((iwtan_association*)context->st_ass + i)->station);
  /*Free all APs*/
  for (i=0;i<context->apN;i++)
    iwtan_free_AP((iwtan_ap*)(*(context->ap_list + i)));
  free(context->ap_ass);
  free(context->st_ass);
  free(context->ap_list);
  if (pthread_mutex_unlock(&(context->mutex))) return -1;
  if (pthread_mutex_destroy(&(context->mutex))) return -1;
  return 0;
}

/* +++++++++++++++++++++++ DATA BROWSING FUNCTIONS ++++++++++++++++++++++++++ */

/*
  Get a linked list of wi_stations_el containing a copy of the stations currently part of the BSS with the given id.
  All the stations properties are copied so that they may be used thread-safely.
  The function iwtan_free_stations_ll() should be called when the list and the stations are no longer needed.
  Returns NULL if no associations were found, otherwise a reference to the first element of the list.
  Function is thread-safe.*/
iwtan_station_el* iwtan_get_by_AP(mac_address* bssId, iwtan_context* context){
  int i;
  pthread_mutex_lock(&(context->mutex));
  iwtan_station_el* ret;

  int firstPos = _iwtan_first_bsearch_by_AP(bssId, context);
  if (firstPos == -1) {
    ret = NULL;
  }
  else {
    unsigned int currentAssI = firstPos;
    iwtan_association* currentAss = context->ap_ass + currentAssI;
    
    iwtan_station_el* firstListEl=calloc(1, sizeof(iwtan_station_el));
    firstListEl->station = _iwtan_copy_station(currentAss->station);
    currentAssI++;
    currentAss = context->ap_ass + currentAssI;

    iwtan_station_el* currListEl = firstListEl;
    while (currentAssI < context->assN && !iwtan_cmp_mac(currentAss->ap->bssId, bssId)){
      currListEl->next = malloc(sizeof(iwtan_station_el));
      currListEl = currListEl->next;
      currListEl->station = _iwtan_copy_station(currentAss->station);
      currListEl->next = NULL;
      currentAssI++;
      currentAss = context->ap_ass + currentAssI;
    }
    ret = firstListEl;
  }
  pthread_mutex_unlock(&(context->mutex));
  return ret;
}

/*
  Get a copy of the access point currently associated to the station with given MAC address.
  All the AP properties are copied so that they may be used thread-safely.
  The function iwtan_free_AP() should be called when the AP is no longer needed.
  Returns NULL if no associations were found, otherwise a reference to the Access Point.
  Function is thread-safe.*/
iwtan_ap* iwtan_get_by_station(mac_address* stMac, iwtan_context* context){
  int i;
  pthread_mutex_lock(&(context->mutex));
  iwtan_ap* ap;
  iwtan_association* ass = context->st_ass + _iwtan_bsearch_by_station(stMac, context);
  ap = (ass==NULL) ? NULL : _iwtan_copy_AP(ass->ap);
  pthread_mutex_unlock(&(context->mutex));
  return ap;
}

/*
  Get a list of (elements referring copies of) all the stations currently present in the database ordered by their MAC address.
  All the stations properties are copied so that they may be used thread-safely.
  The function iwtan_free_stations_ll() should be called when the list and the stations are no longer needed.
  Returns the first element of the list.
  Function is thread-safe.*/
iwtan_station_el* iwtan_get_all_stations(iwtan_context* context){
  pthread_mutex_lock(&(context->mutex));
  iwtan_station_el* ret = NULL;
  if (context->assN != 0){
    int i;
    iwtan_station_el* curr = malloc(sizeof(iwtan_station_el));
    curr->station = _iwtan_copy_station(context->ap_ass->station);
    curr->next = NULL;
    ret = curr;
    for (i=1; i<context->assN; i++){
      curr->next = malloc(sizeof(iwtan_station_el));
      curr = curr->next;
      curr->station = _iwtan_copy_station(((iwtan_association*)(context->ap_ass + i))->station);
      curr->next = NULL;
    }
  }
  
  pthread_mutex_unlock(&(context->mutex));
  return ret;
}

/*
  Get a list of (elements referring copies of) all the Access points currently present in the database ordered by their MAC address.
  All the APs properties are copied so that they may be used thread-safely.
  The function iwtan_free_ap_ll() should be called when the list and the stations are no longer needed.
  Returns the first element of the list.
  Function is thread-safe.
*/
iwtan_ap_el* iwtan_get_all_APs(iwtan_context* context){
  pthread_mutex_lock(&(context->mutex));
  iwtan_ap_el* ret = NULL;
  if (context->apN != 0){
    int i;
    iwtan_ap_el* curr = malloc(sizeof(iwtan_ap_el));
    curr->ap = _iwtan_copy_AP(*(context->ap_list + 0));
    curr->next = NULL;
    ret = curr;
    for (i=1; i<context->apN; i++){
      curr->next = malloc(sizeof(iwtan_ap_el));
      curr = curr->next;
      curr->ap = _iwtan_copy_AP(*(context->ap_list + i));
      curr->next = NULL;
    }
  }
  
  pthread_mutex_unlock(&(context->mutex));
  return ret;
}

/*
  Get an array of (copies of) all the associations between APs and Stations currently present in the database, ordered by the stations MAC address.
  All the elements properties are copied so that they may be used thread-safely.
  The function iwtan_free_ass_array() should be called when the array of associations are no longer needed.
  Returns a pointer to the first element of the array and writes in elementsN the number of element (array size).
  Function is thread-safe.
*/
iwtan_association* iwtan_get_all_associations(iwtan_context* context, unsigned int* elementsN){
  pthread_mutex_lock(&(context->mutex));
  *elementsN = context->assN;
  iwtan_association* associations = calloc(context->assN, sizeof(iwtan_association));
  int i;
  iwtan_association* current;
  iwtan_association* currentNew;
  for (i=0; i<context->assN; i++){
    current = context->st_ass + i;
    currentNew = associations + i;

    currentNew->station = _iwtan_copy_station(current->station);
    currentNew->ap = _iwtan_copy_AP(current->ap);
  }
  pthread_mutex_unlock(&(context->mutex));
  return associations;
}

/* 
   Get an AP with the given essid.
   All the AP properties are copied so that they may be used thread-safely.
   The function iwtan_free_AP() should be called when the AP is no longer needed.
   Returns a pointer to the copied AP or NULL if an AP with the given MAC address was not found.
   Function is thread-safe.
 */
iwtan_ap* iwtan_get_by_essid(char* essid, iwtan_context* context){
  if (!essid) return NULL;
  iwtan_ap* ret = NULL;
  iwtan_ap* current;
  int i=0;
  pthread_mutex_lock(&(context->mutex));
  while (i < context->apN){
    current = *(context->ap_list + i);
    if (current->essid)
      if (!strcmp(current->essid, essid)) {
	ret=_iwtan_copy_AP(current);
	break;
      }
      i++;
  }
  pthread_mutex_unlock(&(context->mutex));
  return ret;
}


/* +++++++++++++++++++++++++++ UTILITY FUNCTIONS ++++++++++++++++++++++++++++ */

/*
  Free an access point and all its elements. Returns 0 only on success.
*/
int iwtan_free_AP(iwtan_ap* ap){
  free(ap->bssId);
  free(ap->essid);
  free(ap->description);
  free(ap);
  return 0;
}

/*
  Free a station and all its elements. Returns 0 only on success.
*/
int iwtan_free_station(iwtan_station* st){
  free(st->mac);  
  free(st->ip4);  
  free(st->ip6);
  free(st);
  return 0;
}

/*
  Free a linked list of iwtan_station_el elements (such as the one created by iwtan_get_by_AP). Free both the elements and the list.
*/
int iwtan_free_stations_ll(iwtan_station_el* freeEl){
  iwtan_station_el* next;
  while (freeEl != NULL){
    next=freeEl->next;
    iwtan_free_station(freeEl->station);
    free(freeEl);
    freeEl=next;
  }
  return 0;
}

/*
  Free a linked list of iwtan_ap_el elements (such as the one created by iwtan_get_all_aps). Free the elements and the list.
*/
int iwtan_free_AP_ll(iwtan_ap_el* freeEl){
  iwtan_ap_el* next;
  while (freeEl != NULL){
    next=freeEl->next;
    iwtan_free_AP(freeEl->ap);
    free(freeEl);
    freeEl=next;
  }
  return 0;
}

/*
  Free all the elements of an array containing associations with the number of elements given by argument. Also frees the array.
*/
int iwtan_free_ass_array(iwtan_association* ass, int size){
  int i;
  iwtan_association* curr;
  for (i=0; i<size; i++){
    curr = ass+i;
    iwtan_free_station(curr->station);
    iwtan_free_AP(curr->ap);
  }
  free(ass);
  return 0;
}

/*
  Compare two mac addresses. Returns 0 if the two given addresses are the same, >0 if mac1>mac2, <0 otherwise. Not thread safe.
*/
int iwtan_cmp_mac(mac_address* mac1, mac_address* mac2){
  int i=0;
  while (i < ETH_ALEN && mac1->ether_addr_octet[i]== mac2->ether_addr_octet[i]) i++;
  if (i==ETH_ALEN)
    return 0;

  return mac1->ether_addr_octet[i] - mac2->ether_addr_octet[i];
}

/*
  Convert an IPv4 address to a string in the standard notation.
  The string will be stored in the address pointed by result, that must be of size 16 at least.
  Returns a pointer to the string or NULL on errors.
*/
char* iwtan_ip4toa(ip4_address ip4, char* result){
  if (!ip4) return NULL;
  sprintf(result, "%d.%d.%d.%d", *(ip4), *(ip4+1), *(ip4+2), *(ip4+3));
  return result;
}

/* Convert an IPv6 address to a string in the standard notation.
   The string will be stored in the address pointed by result, that must be of size 40 at least.
   Returns a pointer to the string or NULL on errors.
*/
char* iwtan_ip6toa(ip6_address ip6, char* result){
  if (!ip6) return NULL;
  int group;
  char* str = result;
  for(group=0; group<8; group++){
    if (*(ip6+group*2)!=0 || *(ip6+group*2+1)!=0){
      sprintf(str, "%.2x%.2x\0", *(ip6+group*2), *(ip6+group*2+1));
      str+=4;
    }
    if (group != 7 ) {
      strcpy(str, ":");
      str++;
    }
  }
  return result;
}


/*+++++++++++++++++++ INTERNAL UTILITY FUNCTIONS +++++++++++++++++++++++++++++*/

/*
  Add an association between a wireless station and an access point.
  If the station mac address is already present in the database, the association gets refreshed with the new associated AP. 
  If the AP was not present in the database, a new one is created.
  Returns 0 if the new association has been made, !=0 on errors.
*/
int _iwtan_add_association(mac_address* bssId, mac_address* station_mac, iwtan_context* context){
  if (bssId == NULL || station_mac == NULL) return 1;

  /* Search for previousely existing associations for the station MAC address*/
  iwtan_station* station;
  int prevPos = _iwtan_bsearch_by_station(station_mac, context);
  if (prevPos == -1){
    /*If the station is not present, we have to create it*/
    station = calloc(1, sizeof(iwtan_station));
    _iwtan_init_station(station_mac, station);

    iwtan_ap** ap_ref = _iwtan_bsearch_AP(bssId, context);
    iwtan_ap* ap=NULL;
    if (ap_ref == NULL){
      /*If the access point is not present in the database, we have to create the new access point.*/
      ap = _iwtan_add_new_AP(bssId, context);
    } else
      ap = *ap_ref;
    
    _iwtan_add_new_association(station, ap, context);
    ap->lastSeen = time(NULL);
    ap->associations++;
  }
  else {
    /*If the station is already present, we have to re-associate it to the new access point*/
    iwtan_association* ass = context->st_ass + prevPos;
    ass->station->lastSeen = time(NULL);
    iwtan_ap* oldAP = ass->ap;
    oldAP->associations--;
    iwtan_ap** newAP_ref = _iwtan_bsearch_AP(bssId, context);
    iwtan_ap* newAP;

    if (newAP_ref == NULL){
      /*If the access point is not present in the database, we have to create the new access point.*/
      newAP = _iwtan_add_new_AP(bssId, context);
    } else {
      newAP = *newAP_ref;
    }

    newAP->lastSeen = time(NULL);
    newAP->associations++;
    ass->ap = newAP; //in any case edit the st_ass
    
    /*Find the association in ap_ass to the old access point and copy to it.*/
    int APPosI = _iwtan_first_bsearch_by_AP(oldAP->bssId, context);
    while (iwtan_cmp_mac(station_mac, ((iwtan_association*)(context->ap_ass + APPosI))->station->mac)) APPosI++;
    *(context->ap_ass + APPosI) = *ass;
  }

  /*In any case, reorder the lists.*/
  qsort(context->ap_ass, context->assN, sizeof(*(context->ap_ass)), (int(*)(const void *, const void *))_iwtan_cmp_assoc_by_AP);
  qsort(context->st_ass, context->assN, sizeof(*(context->st_ass)), (int(*)(const void *, const void *))_iwtan_cmp_assoc_by_station);
  
  return 0;
}

/*
  Remove an access point from the list. Returns !=0 if and only if the given AP was not found or it was not empty (its associated stations was not 0). Not thread safe.
*/
int _iwtan_remove_AP (iwtan_ap* ap, iwtan_context* context){
  int i=0;  
  int r=-1;
  if (ap->associations != 0) return -1;
  while((i < context->apN) && (ap != ((iwtan_association*)(context->ap_ass + i))->ap)) i++;
  if (i != context->apN){
    i++;
    while (i<context->apN){
      *(context->ap_ass + i -1) = *(context->ap_ass + i);
      i++;
    }
    iwtan_free_AP(ap);
    r = 0;
  }
  return r;
}

/*
  Add an access point with the given BSS Id to the list of access points. The AP should not be present in the list before calling this function.
  The list gets ordered by the access points MAC address.
  Not thread safe.
  Returns a pointer to the Access Point
*/
iwtan_ap* _iwtan_add_new_AP(mac_address* bssId, iwtan_context* context){
  if (context->apN == context->allAP){
    context->allAP *= 2;
    context->ap_list = realloc(context->ap_list, context->allAP * sizeof(iwtan_ap*));
  }
  iwtan_ap* newAP = calloc(1, sizeof(iwtan_ap));
  _iwtan_init_AP(bssId, newAP);
  *(context->ap_list + context->apN) = newAP;
  context->apN++;
  qsort(context->ap_list, context->apN, sizeof(iwtan_ap*), (int(*)(const void *, const void *))_iwtan_cmp_AP);
  return newAP;
}

/*
  Add an association between a station and an AP to both ap_ass and st_ass.
  Note that no other corrispondences for that station should exist before.
  The list is not ordered and must be ordered after calling this function.
  The context mutex must be locked before calling this function (i.e. this function is not thread-safe).
  Returns 0 only on success.
*/
int _iwtan_add_new_association(iwtan_station* station, iwtan_ap* ap, iwtan_context* context){
  /* To preserve memory, if the allocated space is three times bigger than the contained elements, it get reduced to a third.*/
  if (context->allAss > 2*context->assN+10){
    context->allAss = context->allAss/2 + 1;
    context->ap_ass = realloc(context->ap_ass, context->allAss * sizeof(iwtan_association));
    context->st_ass = realloc(context->st_ass, context->allAss * sizeof(iwtan_association));    
  }
  /* If there is not enought allocated memory, the space is doubled.*/
  else if (context->allAss == context->assN){
    context->allAss *= 2;
    context->ap_ass = realloc(context->ap_ass, context->allAss * sizeof(iwtan_association));
    context->st_ass = realloc(context->st_ass, context->allAss * sizeof(iwtan_association));    
  }

  iwtan_association* newApAss = context->ap_ass + context->assN;
  newApAss->station = station;
  newApAss->ap = ap;
  iwtan_association* newStAss = context->st_ass + context->assN;
  newStAss->station = station;
  newStAss->ap = ap;

  context->assN++;
  return 0;
}

/*
  Update the data of an Access Point with those passed by argument.
  Arguments are considered (and data is updated) only if their values are significant.
  For pointer-arguments, the old data is freed and replaced with the argument only if the old and new pointer are not the same.
  ap: the AP to update.
  wepped: 1 => wepped, 0 => not wepped, -1 => not significant.
  dataRate: the data rate in Mbps. 0 => not significant.
  antenna: the antenna number. 0 => non significant.
  frequency: the frequency in MHz. 0 => non significant.
  type: the AP type (see iwtan_ap). 0 => non significant.
  signal: the signal strenght. 0 => non significant.
  mac: a pointer to the AP MAC address. NULL => non significant.
  bssId: a pointer to the AP BSS id. NULL => non significant.
  essid: a pointer to the AP essid string. NULL => non significant.
  description: a pointer to the AP description set by the user. NULL => non significant.
  lastSeen: the time this access point was seen for the last time. NULL => non significant.
*/
int _iwtan_update_AP (iwtan_ap* ap, short wepped, unsigned int dataRate, unsigned short antenna, unsigned int frequency, short type, short signal, mac_address* bssId, char* essid, char* description, time_t lastSeen){
  if (wepped != -1) ap->WEPped = wepped;
  if (dataRate != 0) ap->dataRate = dataRate;
  if (antenna != 0) ap->antenna = antenna;
  if (frequency != 0) ap->frequency = frequency;
  if (type !=0) ap->type = type;
  if (signal != 0) ap->signal = signal;
  if (bssId && (bssId != ap->bssId)) {
    free(ap->bssId);
    ap->bssId = bssId;
  }
  if (essid && (essid != ap->essid)) {
    free(ap->essid);
    ap->essid = essid;
  }
  if (description && (description != ap->description)){
    free(ap->description);
    ap->description = description;
  }
  if (lastSeen)
    ap->lastSeen = lastSeen;
}

/*
  Update the data of a Station with those passed by argument.
  Arguments are considered (and data is updated) only if their values are significant.
  For pointer-arguments, the old data is freed and replaced with the argument only if the old and new pointer are not the same.
  st: the station to update.
  ip4: a pointer to the station IPv4. NULL => non significant.
  mac: a pointer to the station MAC address. NULL => non significant.
  ip6: a pointer to the station IPv6. NULL => non significant.
  lastSeen: the time this station was seen for the last time. 0 => non significant.
*/
int _iwtan_update_station (iwtan_station* st, ip4_address ip4, mac_address* mac, ip6_address ip6, time_t lastSeen){
  if (ip4 && (ip4 != st->ip4)){
    free(st->ip4); //TODO: may be optimized...
    st->ip4 = ip4;
  }
  if (mac && (mac != st->mac)) {
    free(st->mac);
    st->mac = mac; 
  }
  if (ip6 && (ip6 != st->ip6)) {
    free(st->ip6);
    st->ip6 = ip6; 
  }
  if (lastSeen)
    st->lastSeen = lastSeen;
}


/*
  Makes a binary search and returns the position in st_ass of the association whose Station MAC address is the one given by argument.
  Returns -1 if such an element is not found. The associations list must be ordered by the Station MAC address.
*/
int _iwtan_bsearch_by_station (mac_address* st_mac, iwtan_context* con){
  iwtan_association hypApAss; //an hypotetical association whose Station has the given mac address
  iwtan_station hypSt;
  hypApAss.station = &hypSt;
  hypSt.mac = st_mac;

  iwtan_association* el = bsearch(&hypApAss, con->st_ass, con->assN, sizeof(iwtan_association), (int(*)(const void*, const void*))_iwtan_cmp_assoc_by_station);
  if (el==NULL) return -1;
  
  return el - con->st_ass;
}

/*
  Search for a station with the given MAC address. Returns a pointer to the station or NULL if not found.
*/
iwtan_station*  _iwtan_bsearch_station(mac_address* st_mac, iwtan_context* con){
  iwtan_association* ass = NULL;
  unsigned int idx = _iwtan_bsearch_by_station(st_mac, con);
  if (idx != -1) ass = con->st_ass + idx;
  return ass ? ass->station : NULL;
}


/*
  Search for an access point in the list and return its index. The context mutex must be locked before calling this function. Returns a pointer to the address where the Access Point is allocated.
*/
iwtan_ap** _iwtan_bsearch_AP(mac_address* bssId, iwtan_context* context){
  iwtan_ap hypAP;
  const iwtan_ap* hypAP_ref = &hypAP;
  hypAP.bssId = bssId;
  return bsearch(&hypAP_ref, context->ap_list, context->apN, sizeof(iwtan_ap*), (int(*)(const void*, const void*))_iwtan_cmp_AP);
}

/*
  Makes a binary search and returns the position of the first association whose Access Point MAC address is the one given by argument.
  Returns -1 if such an element is not found.
  The associations list must be ordered by the Access Point MAC address.
  The context mutex must be locked before calling this function.
*/
int _iwtan_first_bsearch_by_AP(mac_address* bssId, iwtan_context* con){
  iwtan_association hypApAss; //an hypotetical association whose AP has the given mac address
  iwtan_ap hypAP;
  hypApAss.ap = &hypAP;
  hypAP.bssId = bssId;

  iwtan_association* el = bsearch(&hypApAss, con->ap_ass, con->assN, sizeof(iwtan_association), (int(*)(const void*, const void*))_iwtan_cmp_assoc_by_AP);
  if (el==NULL) return -1;
  
  unsigned int i = el - con->ap_ass; //last certian element
  iwtan_association* assNext;
  while (i>=1){
    assNext = con->ap_ass+i-1;
    if (iwtan_cmp_mac(assNext->ap->bssId, bssId)) return i;
    i--;
  }
  return 0;
}

/*
  Initialize an empty AP with the given MAC address
*/
int _iwtan_init_AP(mac_address* bssId, iwtan_ap* ap){
  ap->bssId = bssId;
  ap->associations=0;
  ap->lastSeen = time(NULL);
  return 0;
}

/*
  Initialize a station with the given mac address
*/
int _iwtan_init_station(mac_address* st_mac, iwtan_station* station){
  station->mac = st_mac;
  station->lastSeen = time(NULL);
  return 0;
}  

/*
  Compare two associations by their Access Point mac address.
*/
int _iwtan_cmp_assoc_by_AP(const iwtan_association* ass1, const iwtan_association* ass2){
  return iwtan_cmp_mac(ass1->ap->bssId, ass2->ap->bssId);
}

/*
  Compare two associations by their station mac address
*/
int _iwtan_cmp_assoc_by_station(const iwtan_association* ass1, const iwtan_association* ass2){
  return iwtan_cmp_mac(ass1->station->mac, ass2->station->mac);
}

/*
  Compare two access points by their BSS Id.
*/
int _iwtan_cmp_AP(const iwtan_ap** ap1_ref, const iwtan_ap** ap2_ref){
  const iwtan_ap* ap1 = *ap1_ref;
  const iwtan_ap* ap2 = *ap2_ref;
  return iwtan_cmp_mac(ap1->bssId, ap2->bssId);
}

/*
  Returns a copy of the station given by argument, with all its elements copied.
*/
iwtan_station* _iwtan_copy_station (iwtan_station* st){
  iwtan_station* newStation = calloc(1, sizeof(iwtan_station));
  newStation->ip4 = _iwtan_copy_ip4(st->ip4);
  newStation->ip6 = _iwtan_copy_ip6(st->ip6);
  newStation->mac = _iwtan_copy_mac(st->mac);
  newStation->lastSeen = st->lastSeen;
  return newStation;
}

/*
  Returns a copy of the Access Point given by argument, with all its elements copied.
*/
iwtan_ap* _iwtan_copy_AP (iwtan_ap* ap){
  iwtan_ap* newAP = calloc(1, sizeof(iwtan_ap));
  
  *newAP = *ap;
  if (ap->essid){
    newAP->essid = calloc(strlen(ap->essid) + 1, sizeof(char));
    strcpy(newAP->essid, ap->essid);
  } else 
    newAP->essid = NULL;

  if (ap->description){
    newAP->description = calloc(strlen(ap->description) + 1, sizeof(char));
    strcpy(newAP->description, ap->description);}

  newAP->bssId = _iwtan_copy_mac(ap->bssId);

  return newAP;
}

/*
  Returns a copy of the IPv4 address given by argument.
*/
ip4_address _iwtan_copy_ip4(ip4_address ip4){
  if (!ip4) return NULL;
  ip4_address newIP4 = calloc(IWTAN_IP4_LEN, sizeof(uint8_t));
  int i;
  for(i=0;i<IWTAN_IP4_LEN; i++)
    *(newIP4+i) = *(ip4+i);
  return newIP4;
}

/*
  Returns a copy of the IPv6 address given by argument.
*/
ip6_address _iwtan_copy_ip6(ip6_address ip6){
  if (!ip6) return NULL;
  ip6_address newIP6 = calloc(IWTAN_IP6_LEN, sizeof(uint8_t));
  int i;
  for(i=0;i<IWTAN_IP6_LEN; i++)
    *(newIP6 + i) = *(ip6 + i);
  return newIP6;
}

/*
  Returns a copy of the MAC address given by argument.
*/
mac_address* _iwtan_copy_mac(mac_address* mac){
  if (!mac) return NULL;
  mac_address* newMac = malloc(sizeof(mac_address));
  int i;
  for(i=0;i<sizeof(mac_address); i++)
    newMac->ether_addr_octet[i] = mac->ether_addr_octet[i];
  return newMac;
}

/*
  Copy a newly allocated MAC address with the bytes pointed by array.
*/
mac_address* _iwtan_copy_mac_by_array(uint8_t* array){
  if (!array) return NULL;
  mac_address* newMac = malloc(sizeof(mac_address));
  int i;
  for(i=0;i<sizeof(mac_address); i++)
    newMac->ether_addr_octet[i] = *(array+i);
  return newMac;
}
