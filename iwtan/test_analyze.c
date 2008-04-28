#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <iwlib.h>
#include <netinet/ether.h>

#include "iwtan_analyze.h"

int main (int argc, char** argv){
  pcap_t* handle;
  pcap_addr_t* addrI=NULL;
  char* ebuf = calloc(PCAP_ERRBUF_SIZE, sizeof(char));
  int snaplen = 65535;
  int pktDlt;
  const u_char *packetBody;	
  struct pcap_pkthdr header;
  if (argc<2) {
    printf ("give a file name to read packets from as first argument\n");
    exit(-1);
  }
  char* inputFileName = *(argv+1);
  
  printf("Bit test:\n");

  printf("0th bit of 128 is: %d (1)\n0th bit of 127 is: %d (0)\n6th bit of 2 is: %d(1)\n6th bit of 1 is: %d (0)\n7th bit of 255 is: %d (1)\n1st bit of 255 is: %d (1)\n\n", _iwtan_byte_to_bool(128,0), _iwtan_byte_to_bool(127,0), _iwtan_byte_to_bool(2,6), _iwtan_byte_to_bool(1,6), _iwtan_byte_to_bool(255,7), _iwtan_byte_to_bool(255,1));
  fflush(stdout);


  printf("Notation tests\n");
  ip6_address ipv6 = malloc(sizeof(uint8_t)*IWTAN_IP6_LEN);
  *(ipv6 + 0) = 0x25;
  *(ipv6 + 1) = 0x01;
  *(ipv6 + 2) = 0x0d;
  *(ipv6 + 3) = 0xb8;
  *(ipv6 + 4) = 0x00;
  *(ipv6 + 5) = 0x00;
  *(ipv6 + 6) = 0x00;
  *(ipv6 + 7) = 0x00;
  *(ipv6 + 8) = 0x00;
  *(ipv6 + 9) = 0x00;
  *(ipv6 + 10) = 0x00;
  *(ipv6 + 11) = 0x00;
  *(ipv6 + 12) = 0x14;
  *(ipv6 + 13) = 0x28;
  *(ipv6 + 14) = 0x57;
  *(ipv6 + 15) = 0xab;
  char* buf_ipv6 = calloc(40, sizeof(char));
  printf ("IPv6 standard notation: %s ", iwtan_ip6toa(ipv6, buf_ipv6));
  printf ("address is broadcast: %d\n", _iwtan_ip6_is_broadcast(ipv6));

  *(ipv6 + 15) = 0xff;
  printf ("IPv6 standard notation: %s ", iwtan_ip6toa(ipv6, buf_ipv6));
  printf ("address is broadcast: %d\n", _iwtan_ip6_is_broadcast(ipv6));

  *(ipv6 + 14) = 0xff;
  printf ("IPv6 standard notation: %s ", iwtan_ip6toa(ipv6, buf_ipv6));
  printf ("address is broadcast: %d\n\n", _iwtan_ip6_is_broadcast(ipv6));

  free(buf_ipv6);
  free(ipv6);

  ip4_address ipv4 = malloc(sizeof(uint8_t)*IWTAN_IP4_LEN);
  *(ipv4 + 0) = 192;
  *(ipv4 + 1) = 168;
  *(ipv4 + 2) = 1;
  *(ipv4 + 3) = 25;
  char* buf_ipv4 = calloc(16, sizeof(char));
  printf ("IPv4 standard notation: %s ", iwtan_ip4toa(ipv4, buf_ipv4));
  printf ("address is broadcast: %d\n", _iwtan_ip4_is_broadcast(ipv4));
  *(ipv4 + 3) = 255;
  printf ("IPv4 standard notation: %s ", iwtan_ip4toa(ipv4, buf_ipv4));
  printf ("address is broadcast: %d\n\n", _iwtan_ip4_is_broadcast(ipv4));
  
  *(ipv4 + 0) = 255;
  *(ipv4 + 1) = 255;
  *(ipv4 + 2) = 255;
  *(ipv4 + 3) = 255;
  printf ("IPv4 standard notation: %s ", iwtan_ip4toa(ipv4, buf_ipv4));
  printf ("address is broadcast: %d\n\n", _iwtan_ip4_is_broadcast(ipv4));

  free(buf_ipv4);
  free(ipv4);

  char* macBuf = calloc (18,sizeof(char));
  mac_address* mac = malloc(sizeof(mac_address));
  mac->ether_addr_octet[0] = 0xff;
  mac->ether_addr_octet[1] = 0xff;
  mac->ether_addr_octet[2] = 0xff;
  mac->ether_addr_octet[3] = 0xff;
  mac->ether_addr_octet[4] = 0xff;
  mac->ether_addr_octet[5] = 0xff;
  printf ("MAC standard notation: %s\n", ether_ntoa_r(mac, macBuf));
  printf ("address is broadcast: %d\n\n", _iwtan_mac_is_broadcast(mac));
  mac->ether_addr_octet[3] = 0x24;
  printf ("MAC standard notation: %s\n", ether_ntoa_r(mac, macBuf));
  printf ("address is broadcast: %d\n\n", _iwtan_mac_is_broadcast(mac));
  

  free(mac);
  free(macBuf);


  printf ("Reading from file: %s\n", inputFileName);
  
  handle = pcap_open_offline(inputFileName,ebuf);
  
  if (handle == NULL) {
    fprintf(stderr, "Couldn't obtain packets data from file %s for the following problem: %s\n", inputFileName, ebuf);
    exit(EXIT_FAILURE);
  }

  //data obtained by the radiotap header
  short WEPped = -1;
  unsigned int dataRate = 0;
  short antenna = -1;
  unsigned int frequency = 0;
  short type = 0;
  short signal = 0;
  int headerLength=0;
  
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
  /*  mac_address* srcMac = NULL;
  mac_address* destMac = NULL;
  ip4_address srcIp4 = NULL;
  ip6_address srcIp6 = NULL;
  ip4_address destIp4 = NULL;
  ip6_address destIp6 = NULL;
  */


  while ((packetBody = pcap_next(handle, &header))!=NULL) {
    pktDlt = pcap_datalink(handle);
    printf("\nAnalyzing a packet of size [%d] and type [%s]\n", header.len, pcap_datalink_val_to_name(pktDlt));

    //null all obtainable data
    WEPped = -1;
    dataRate = 0;
    antenna = -1;
    frequency = 0;
    type = 0;
    signal = 0;
    stMac = NULL;
    apMac = NULL;
    bssId = NULL;
    essid = NULL;
    stIp4 = NULL;
    stIp6 = NULL;

    

    //determine what's the kind of the analyzed packet
    switch (pktDlt){
    case DLT_IEEE802_11_RADIO: 
      if (_iwtan_validate_radiotap(packetBody, header.len)){
	_iwtan_process_radiotap(packetBody, header.len, &WEPped, &dataRate, &antenna, &frequency, &type, &signal, &stMac, &apMac, &bssId, &essid, &stIp4, &stIp6);
      }
      break;
    case DLT_IEEE802_11:
      _iwtan_process_802_11(packetBody, header.len, &apMac, &stMac, &bssId, &essid, &stIp4, &stIp6);
      break;
    default:
      printf("Cannot process data of this type.\n");
    }

    char* macBuf1 = calloc(18, sizeof(char));
    char* macBuf2 = calloc(18, sizeof(char));
    char* bssIdBuf = calloc(18, sizeof(char));
    char* stIp4Buf = calloc(16, sizeof(char));
    char* stIp6Buf = calloc(40, sizeof(char));
    char* srcIp4Buf = calloc(16, sizeof(char));
    char* srcIp6Buf = calloc(40, sizeof(char));
    char* destIp4Buf = calloc(16, sizeof(char));
    char* destIp6Buf = calloc(40, sizeof(char));
      
    if (pktDlt == DLT_IEEE802_11_RADIO){
      printf ("++++++++ Data obtained by the radiotap header:\nheader lenght: %d\nwepped: %d\ndatarate: %d Mbps\nantenna: %d\nfrequency: %d MHz\ntype: %d\nsignal:%d\n\n", headerLength, WEPped, dataRate, antenna, frequency, type, signal);
    } else 
      printf ("No data about the radiotap can be extracted.\n");
    
    if (pktDlt == DLT_IEEE802_11 || pktDlt == DLT_IEEE802_11_RADIO)
      printf ("++++++++ Data obtained by the 802.11 header:\nAP mac: %s\nSTA mac: %s\nbss ID: %s\nessid: %s\nstation ip4: %s\nstation ip6: %s\n\n", apMac ? ether_ntoa_r(apMac, macBuf1) : NULL, stMac ? ether_ntoa_r(stMac, macBuf2) : NULL, bssId ? ether_ntoa_r(bssId, bssIdBuf) : NULL, essid, iwtan_ip4toa(stIp4, stIp4Buf), iwtan_ip6toa(stIp6, stIp6Buf));
      
    free(macBuf1);
    free(macBuf2);
    free(bssIdBuf);
    free(stIp4Buf);
    free(stIp6Buf);
    free(stMac);
    free(apMac);
    free(bssId);
    free(essid);
    free(stIp4);
    free(stIp6);
  }
  
  pcap_close(handle);
  free(ebuf);  
  
}
