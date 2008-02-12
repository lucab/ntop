#include "iwtan_data.h"
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int print_all_data_dump(iwtan_context* con, mac_address* ap1_mac, mac_address* ap2_mac, mac_address* ap3_mac){
  print_ass_ord_AP(con);
  print_ass_ord_st(con);
  print_AP_list(con);
  printf("search for stations associated to ap1:\n");
  print_get_by_AP(con, ap1_mac);
  printf("search for stations associated to ap2:\n");
  print_get_by_AP(con, ap2_mac);
  printf("search for stations associated to ap3:\n");
  print_get_by_AP(con, ap3_mac);
}

int print_cmp_mac(mac_address* mac1, mac_address* mac2){
  printf("%s ", ether_ntoa(mac1));
  if (iwtan_cmp_mac(mac1, mac2) ==0 ) printf("=");
  else if (iwtan_cmp_mac(mac1, mac2) < 0 ) printf("<");
  else printf(">");
  printf (" %s\n",ether_ntoa(mac2));
}

int print_get_by_AP(iwtan_context* cont, mac_address* ap_mac){
  char* macBuff1 = calloc (18,sizeof(char));
  char* macBuff2 = calloc (18,sizeof(char));
  iwtan_station_el* current;
  iwtan_station_el* first;
  printf("Got by AP == [%s]\n", ether_ntoa_r(ap_mac, macBuff1));
  first = iwtan_get_by_AP(ap_mac, cont);
  current = first;
  if (current==NULL) printf ("(no stations found)\n");
  while (current != NULL){
    printf("%s  --> %s\n", ether_ntoa_r(current->station->mac, macBuff2), ether_ntoa_r(ap_mac, macBuff1));
    current = current->next;
  }
  iwtan_free_stations_ll(first);
  printf("\n");
  free(macBuff1);
  free(macBuff2);
}

int print_ass_ord(iwtan_context* cont, int ordering){
  char* macBuff1 = calloc (18,sizeof(char));
  char* macBuff2 = calloc (18,sizeof(char));
  char* timeBuff1 = calloc (26, sizeof(char));
  char* timeBuff2 = calloc (26, sizeof(char));

  (ordering==0) ? printf("AP ordering:\n") : printf("Station ordering:\n");
  printf("Number of associations: %i\nNumber of allocated ass: %i\n", cont->assN, cont->allAss);
  int i;
  iwtan_association* assI;
  for (i=0; i < cont->assN ; i++){
    assI = (ordering==0) ? cont->ap_ass + i : cont->st_ass + i;
    ctime_r(&(assI->station->lastSeen), timeBuff1);   
    ctime_r(&(assI->ap->lastSeen), timeBuff2);
    int j=0;
    while (*(timeBuff1+j) != '\n') j++; *(timeBuff1+j) = '\0';
    while (*(timeBuff2+j) != '\n') j++; *(timeBuff2+j) = '\0';

    printf("%s (%p) (last seen: %s)--> %s (%p) (last seen: %s)\n", ether_ntoa_r(assI->station->mac, macBuff1), assI->station, timeBuff1, ether_ntoa_r(assI->ap->mac, macBuff2), assI->ap, timeBuff2);
  }
  printf("\n");
  free(macBuff1);
  free(macBuff2);
  free(timeBuff1);
  free(timeBuff2);
}

int print_AP_list(iwtan_context* cont){
  printf("AP List:\ncontains %d elements.\n", cont->apN);
  int i;
  for (i=0; i< cont->apN; i++){
    iwtan_ap* apI = *(cont->ap_list + i);
    printf("%i: %s %p [associations: %d]\n", i, ether_ntoa(apI->mac), apI, apI->associations);
  }
}

int print_ass_ord_AP(iwtan_context* cont){
  print_ass_ord(cont, 0);
}

int print_ass_ord_st(iwtan_context* cont){
  print_ass_ord(cont, 1);
}

int main (int argc, char** argv){
  iwtan_context con;
  iwtan_context_initialize(&con) ? printf("ERROR: could not create context\n") : printf("OK: context created.\n");

  printf("+++ Sizeof summary +++\n mac_address: %d\n ip4_address: %d\n ip6_address: %d\n iwtan_ap: %d\n iwtan_station: %d\n iwtan_station_el: %d\n iwtan_association: %d\n iwtan_context: %d\n\n", sizeof(mac_address), sizeof(ip4_address), sizeof(ip6_address), sizeof(iwtan_ap), sizeof(iwtan_station), sizeof(iwtan_station_el), sizeof(iwtan_association), sizeof (iwtan_context));
  
  mac_address* ap1_mac = calloc(1, sizeof(mac_address));
  ap1_mac->ether_addr_octet[0]=20; 
  ap1_mac->ether_addr_octet[1]=20; 
  ap1_mac->ether_addr_octet[2]=20; 
  ap1_mac->ether_addr_octet[3]=20; 
  ap1_mac->ether_addr_octet[4]=20; 
  ap1_mac->ether_addr_octet[5]=30; 
  printf("AP1 mac: %s\n", ether_ntoa(ap1_mac));

  mac_address* ap2_mac = calloc(1, sizeof(mac_address));
  ap2_mac->ether_addr_octet[0]=20; 
  ap2_mac->ether_addr_octet[1]=20; 
  ap2_mac->ether_addr_octet[2]=20; 
  ap2_mac->ether_addr_octet[3]=20; 
  ap2_mac->ether_addr_octet[4]=20; 
  ap2_mac->ether_addr_octet[5]=20; 
  printf("AP2 mac: %s\n", ether_ntoa(ap2_mac));

  mac_address* ap3_mac = calloc(1, sizeof(mac_address));
  ap3_mac->ether_addr_octet[0]=30; 
  ap3_mac->ether_addr_octet[1]=30; 
  ap3_mac->ether_addr_octet[2]=30; 
  ap3_mac->ether_addr_octet[3]=30; 
  ap3_mac->ether_addr_octet[4]=30; 
  ap3_mac->ether_addr_octet[5]=30; 
  printf("AP3 mac: %s\n", ether_ntoa(ap3_mac));
  
  mac_address* st1_mac = calloc(1, sizeof(mac_address));
  st1_mac->ether_addr_octet[0]=50; 
  st1_mac->ether_addr_octet[1]=50; 
  st1_mac->ether_addr_octet[2]=50; 
  st1_mac->ether_addr_octet[3]=50; 
  st1_mac->ether_addr_octet[4]=50; 
  st1_mac->ether_addr_octet[5]=50; 
  printf("ST1 mac: %s\n", ether_ntoa(st1_mac));

  mac_address* st2_mac = calloc(1, sizeof(mac_address));
  st2_mac->ether_addr_octet[0]=60; 
  st2_mac->ether_addr_octet[1]=60; 
  st2_mac->ether_addr_octet[2]=60; 
  st2_mac->ether_addr_octet[3]=60; 
  st2_mac->ether_addr_octet[4]=60; 
  st2_mac->ether_addr_octet[5]=60; 
  printf("ST2 mac: %s\n", ether_ntoa(st2_mac));

  mac_address* st3_mac = calloc(1, sizeof(mac_address));
  st3_mac->ether_addr_octet[0]=60; 
  st3_mac->ether_addr_octet[1]=60; 
  st3_mac->ether_addr_octet[2]=60; 
  st3_mac->ether_addr_octet[3]=60; 
  st3_mac->ether_addr_octet[4]=61; 
  st3_mac->ether_addr_octet[5]=60; 
  printf("ST3 mac: %s\n", ether_ntoa(st3_mac));

  mac_address* eq_mac = calloc(1, sizeof(mac_address));
  eq_mac->ether_addr_octet[0]=50; 
  eq_mac->ether_addr_octet[1]=50; 
  eq_mac->ether_addr_octet[2]=50; 
  eq_mac->ether_addr_octet[3]=50; 
  eq_mac->ether_addr_octet[4]=50; 
  eq_mac->ether_addr_octet[5]=50; 
  printf("EQ1 mac: %s\n", ether_ntoa(eq_mac));


  
  printf("+++ MAC Comparison test +++\n");
  print_cmp_mac(ap1_mac, ap2_mac);
  print_cmp_mac(ap2_mac, ap1_mac);
  print_cmp_mac(ap1_mac, st1_mac);
  print_cmp_mac(eq_mac, st1_mac);
  print_cmp_mac(st1_mac, st2_mac);
  print_cmp_mac(st3_mac, st2_mac);

  printf("+++ Empty context test +++\n");
  print_ass_ord_AP(&con);
  print_ass_ord_st(&con);
  printf("search for stations associated to ap1:\n");
  print_get_by_AP(&con, ap1_mac);
  


  printf("\n+++ AddAssociation +++\n(st1 is associated to ap1)\n");
  (_iwtan_add_association(ap1_mac, st1_mac, &con)) ? printf("ERROR: Could not set a new association between ap1 and st1\n") : printf("OK: st1 associated to ap1\n");

  print_all_data_dump(&con, ap1_mac, ap2_mac, ap3_mac);
  
  printf("(st2 is associated to ap2)\n");
  (_iwtan_add_association(ap2_mac, st2_mac, &con)) ? printf("ERROR: Could not set a new association between ap2 and st2\n") : printf("OK: st2 associated to ap2\n");

  print_all_data_dump(&con, ap1_mac, ap2_mac, ap3_mac);
  
  printf("(st2 is associated to ap2 again)\n");
  (_iwtan_add_association(ap2_mac, st2_mac, &con)) ? printf("ERROR: Could not renew the association between ap2 and st2\n") : printf("OK: st2 is still associated to ap2\n");
  print_all_data_dump(&con, ap1_mac, ap2_mac, ap3_mac);

  printf("(st2 is now associated to ap3)\n");
  (_iwtan_add_association(ap3_mac, st2_mac, &con)) ? printf("ERROR: Could not change the association os st2 to ap3\n") : printf("OK: st2 is now associated to ap3\n");
  print_all_data_dump(&con, ap1_mac, ap2_mac, ap3_mac);

  printf("(st3 is now associated to ap3)\n");
  (_iwtan_add_association(ap3_mac, st3_mac, &con)) ? printf("ERROR: Could not change the association of st3 to ap3\n") : printf("OK: st3 is now associated to ap3\n");
  print_all_data_dump(&con, ap1_mac, ap2_mac, ap3_mac);

  //trying other browsing functions...

  // get an AP by its station
  iwtan_ap* ap =  iwtan_get_by_station(st3_mac, &con);
  printf("\n+++++++ OTHER BROWSING FUNCTIONS +++++++");
  printf ("\nget AP by station - Station:[%s] ", ether_ntoa(st3_mac));
  printf ("returned AP: [%s]\n", ether_ntoa(ap->mac));
  iwtan_free_AP(ap);

  
  //get all stations linked list
  iwtan_station_el* first = iwtan_get_all_stations(&con);
  iwtan_station_el* current = first;
  iwtan_station* currSt;
  printf ("\nlist of all the stations filed in the database (ordered by mac):\n");
  while (current){
    currSt = current->station;
    printf("[%s]\n", ether_ntoa(currSt->mac));
    current = current->next;
  }
  iwtan_free_stations_ll(first);




    //get all AP linked list
  iwtan_ap_el* first_ap_el = iwtan_get_all_APs(&con);
  iwtan_ap_el* current_ap_el = first_ap_el;
  iwtan_ap* currAP;
  printf ("\nlist of all the AP filed in the database (ordered by mac):\n");
  while (current_ap_el){
    currAP = current_ap_el->ap;
    printf("[%s]\n", ether_ntoa(currAP->mac));
    current_ap_el = current_ap_el->next;
  }
  iwtan_free_AP_ll(first_ap_el);

  
  //get all Associations
  int elN;
  iwtan_association* ass_b = iwtan_get_all_associations(&con, &elN);
  iwtan_association* ass_i;
  iwtan_ap* ap_i;
  iwtan_station* st_i;
  printf("\nlist all the associations ordered by station mac address:\n");
  int i;
  for (i=0; i<elN; i++){
    ass_i = ass_b + i;
    ap_i = ass_i->ap;
    st_i = ass_i->station;
    printf("[%s] --> ", ether_ntoa(st_i->mac));
    printf("[%s]\n", ether_ntoa(ap_i->mac));
  }
  
  iwtan_free_ass_array(ass_b,elN);


  iwtan_context_destroy(&con) ? printf("ERROR: could not destroy context\n") : printf("OK: context destroyed.\n");
}

