#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <iwlib.h>
#include <signal.h>
#include <time.h>

#include "iwtan_example.h"
#include "iwtan_data.h"
#include "iwtan_analyze.h"


char* inputFileName=NULL;
char* inputDev=NULL;
char* ebuf;
pcap_t* handle;
iwtan_context context;
unsigned int processedPkts=0;
unsigned int totalLength=0;
clock_t start;

int main (int argc, char** argv){
  pcap_if_t* ifI = NULL;
  pcap_addr_t* addrI=NULL;
  ebuf = calloc(PCAP_ERRBUF_SIZE, sizeof(char));
  int snaplen = 65535;
  int promisc = 1;
  int timeout = 1000;
  int pktDlt;
  const u_char *packet;	
  struct pcap_pkthdr header;
  iwtan_context_initialize(&context);

  struct sigaction sigact;
  memset(&sigact, 0, sizeof(struct sigaction));
  sigact.sa_handler = (void(*)(int))end;
  sigaction(SIGINT, &sigact, NULL);

  sigset_t blocking;
  sigemptyset(&blocking);
  pthread_sigmask(SIG_SETMASK, &blocking, NULL);


  if (parseArgs(argc,argv)==NULL){
    printf("Please use the command line arguments as described in the manual (TODO)\n");
    exit(EXIT_FAILURE);
  }
  if (inputFileName!=NULL) {
    printf ("Reading from file: %s\n", inputFileName);
    inputDev=NULL;
  }
  else if (inputDev!=NULL)
    printf ("Reading from device: %s\n", inputDev);
  else {
    printf("You have to specify a file (with -f) or a device (with -d) to read packets from.\n");
    exit(EXIT_FAILURE);
  }

  fflush(stdout);
  
  
  handle = (inputFileName==NULL)? pcap_open_live(inputDev, snaplen, promisc, timeout, ebuf) : pcap_open_offline(inputFileName,ebuf);
  
  if (handle == NULL) {
    if (inputFileName==NULL)
      fprintf(stderr, "Couldn't obtain packets data from device %s for the following problem: %s\n", inputDev, ebuf);
    else
      fprintf(stderr, "Couldn't obtain packets data from file %s for the following problem: %s\n", inputFileName, ebuf);
    exit(EXIT_FAILURE);
  }

  start = clock();
  
  sigset_t pending;
  while ((packet = pcap_next(handle, &header))!=NULL) {
    //deactivate SIGINT (will be blocked and queued to avoid iwtan data inconsistency.)
    sigaddset(&blocking, SIGINT);
    pthread_sigmask(SIG_SETMASK, &blocking, NULL);

    pktDlt = pcap_datalink(handle);
    //printf("Analyzing a packet of length [%d] and type [%s]\n", header.len, pcap_datalink_val_to_name(pktDlt));
    iwtan_refresh_data(header.len, packet, pktDlt, &context);
    processedPkts++;
    totalLength += header.len;

    //if a SIGINT signal is pending, call the end() function.
    sigpending(&pending);
    if (sigismember(&pending, SIGINT))
      end();

    //reactivate SIGINT (will be called end() if SIGINT is received when waiting for the next packet capture)
    sigdelset(&blocking, SIGINT);
    pthread_sigmask(SIG_SETMASK, &blocking, NULL);
    
  }


  end();
  
}

int end (){
  pcap_close(handle);
  
  printDump(&context); 
  
  free(ebuf);
  iwtan_context_destroy(&context);
  
  exit(EXIT_SUCCESS);
}

/*sets global variables and returns the list of files to process or
  NULL in case of argument error*/
char** parseArgs(int argc, char**argv){
  int optionIndex = 0;
  int a;
  
  opterr=0;
  struct option longOptions[]={
    {"file", 1, 0, 'f'},
    {"dev", 1, 0, 'd'}
  };
	
  while ((a = getopt_long (argc, argv, "f:d:", longOptions, &optionIndex)) !=-1 ){
    switch (a){
    case ('f'):
      inputFileName=optarg;
      break;
    case ('d'):
      inputDev=optarg;
      break;
    default: 
      fprintf(stderr, "Invalid option: %c\n",optopt);
      return NULL;
    }
  }
  return argv+optind;
}



int printDump(iwtan_context* con){
  printf("\t\t+++ Data contained in the context +++\n\n");
  unsigned int elementsN;
  iwtan_association* ass = iwtan_get_all_associations(con, &elementsN);
  iwtan_association* currAss;

  printf("\t--- Stations: ---\n");
  if (!elementsN) printf("No stations found.\n");
  int i;
  for (i=0; i<elementsN;i++){
    currAss = ass+i;
    printStation(currAss->station, currAss->ap, i);
  }
  iwtan_free_ass_array(ass, elementsN);

  printf("\t--- Access Points: ---\n");
  iwtan_ap_el* firstAp = iwtan_get_all_APs(con);
  if (!firstAp) printf("No AP found.\n");
  iwtan_ap_el* currentAp = firstAp;
  while (currentAp){
    printAP(currentAp->ap);
    currentAp = currentAp->next;
  }
  iwtan_free_AP_ll(firstAp);
  
  clock_t elaspedMsec = (clock()-start)*1000/CLOCKS_PER_SEC;
  float processRate = (elaspedMsec) ? processedPkts/elaspedMsec : 0;
  printf("Processed %d packets for a total length of %d kbytes in %d msec.\n", processedPkts, totalLength/1024, elaspedMsec);
  (processRate<1000) ? printf("(processed %.2f pkts/msec).\n",processRate) : printf("(%.2f pkts/sec).\n",processRate/1000);

}

int printStation(iwtan_station* sta, iwtan_ap* ap, int i){
  char* stMacBuf = calloc(18,sizeof(char));
  char* apMacBuf = calloc(18,sizeof(char));
  char* stIp4Buf = calloc(16,sizeof(char));
  char* stIp6Buf = calloc(40,sizeof(char));
  char* timeBuf = calloc(26,sizeof(char));
  ctime_r(&(sta->lastSeen), timeBuf);
  int j=0;
  while (*(timeBuf+j) != '\n') j++; *(timeBuf+j) = '\0';
    
  printf("Station n. %d\nMAC: %s\nAssociated to AP: %s (%s)\nIP4: %s\nIP6: %s\nLast seen:%s\n\n",i, ether_ntoa_r(sta->mac, stMacBuf), ether_ntoa_r(ap->bssId, apMacBuf), ap->essid, iwtan_ip4toa(sta->ip4, stIp4Buf), iwtan_ip6toa(sta->ip6, stIp6Buf), timeBuf);

  free (stMacBuf);
  free (apMacBuf);
  free (stIp4Buf);
  free (stIp6Buf);
  free (timeBuf);
}

int printAP(iwtan_ap* ap){
  char* bssidBuf = calloc(18,sizeof(char));
  char* timeBuf = calloc(26,sizeof(char));
  ctime_r(&(ap->lastSeen), timeBuf);
  int j=0;
  while (*(timeBuf+j) != '\n') j++; *(timeBuf+j) = '\0';
  
  printf("Access Point\nBSS ID: %s\n", ether_ntoa_r(ap->bssId, bssidBuf));
  (ap->WEPped) ? printf("WEP is on.\n") : printf("WEP is off.\n");
  printf("Data rate: %d Mbps\nAntenna: %d\nFrequency: %d MHz\n", ap->dataRate, ap->antenna, ap->frequency);
  switch (ap->type){
  case 0: printf("Type: Unknown\n"); break;
  case 1: printf("Type: 802.11b\n"); break;
  }
  printf("Signal strength: %d\n", ap->signal);
  printf("ESSID: %s\nDescription: %s\nAssociated clients: %d\nLast seen:%s\n\n", ap->essid, ap->description, ap->associations, timeBuf);
  
  free (bssidBuf);
  free (timeBuf);
}
