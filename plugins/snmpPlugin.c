/*
 * snmpPlugin.c
 *
 * Copyright (C) 2004 Fusco Francesco   <fuscof@cli.di.unipi.it>
 *                    Giuseppe Giardina <giardina@cli.di.unipi.it>
 *     
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; see the file COPYING.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 */

/*
 * AUTHORS:
 *      Fusco Francesco   <fuscof@cli.di.unipi.it>
 *      Giuseppe Giardina <giardina@cli.di.unipi.it>
 *
 * VERSION: 0.1
 *
 *
 *  This plugin provides snmp support to ntop.
 *  Now you can use it to monitor HostTraffic struct for all the host.
 *  Look at NTOP-MIB too see how you can query traffic for a particular host.
 *
 *  snmpPlugin is under developement so it cannnot work perfectly as you hope for
 *  a ntop plugin. That means that it si not a good idea to use snmpPlugin in production
 *  server.
 *
 */

/*
 * This plugin works only with threads
 */

#include "ntop.h"
#include "globals-report.h"


#ifdef HAVE_SNMP

#define AGENT_NAME       "ntopSnmp"
#define AGENT_ISSUBAGENT 0     /* 0 main agent, 1 sub agentx */
#define AGENT_PORT       161   /* TODO: how to set a different port? */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// #ifndef NTOP_H
#define NTOP_H
// #ifndef NTOP_COLUMNS_H
#define NTOP_COLUMNS_H

/*
 * column number definitions for table ntopTable
 */
#define COLUMN_NTOPSERIALTYPE		1
#define COLUMN_NTOPACTUALDEVICE		2
#define COLUMN_NTOPVANID		3
#define COLUMN_NTOPSERIAL		4
#define COLUMN_HOSTRESOLVEDNAME		5
#define COLUMN_FINGERPRINT		6
#define COLUMN_PKTSENT		        7
#define COLUMN_PKTRCVD		        8
#define COLUMN_PKTSENTSESSION		9
#define COLUMN_PKTRCVDSESSION		10
#define COLUMN_PKTDUPLICATEDACKSENT	11
#define COLUMN_PKTDUPLICATEDACKRCVD	12
#define COLUMN_PKTBROADCASTSENT		13
#define COLUMN_BYTESBROADCASTSENT	14
#define COLUMN_PKTMULTICASTSENT		15
#define COLUMN_BYTESMULTICASTSENT	16
#define COLUMN_PKTMULTICASTRCVD		17
#define COLUMN_BYTESMULTICASTRCVD	18
#define COLUMN_BYTESSENT		19
#define COLUMN_BYTESSENTLOC		20
#define COLUMN_BYTESSENTREM		21
#define COLUMN_BYTESSENTSESSION		22
#define COLUMN_BYTESRCVD		23
#define COLUMN_BYTESRCVDLOC		24
#define COLUMN_BYTESRCVDFROMREM		25
#define COLUMN_BYTESRCVDSESSION		26
#define COLUMN_NUMHOSTSESSIONS		27
#define COLUMN_IPBYTESSENT		28
#define COLUMN_IPBYTESRCVD		29
#define COLUMN_IPV6SENT		        30
#define COLUMN_IPV6RCVD		        31
#define COLUMN_TCPSENTLOC		32
#define COLUMN_TCPSENTREM		33
#define COLUMN_UDPSENTLOC		34
#define COLUMN_UDPSENTREM		35
#define COLUMN_ICMPSENT		        36
#define COLUMN_ICMP6SENT		37
#define COLUMN_TCPRCVDLOC		38
#define COLUMN_TCPRCVDFROMREM		39
#define COLUMN_UDPRCVDLOC		40
#define COLUMN_UDPRCVDFROMREM		41
#define COLUMN_ICMPRCVD		        42
#define COLUMN_ICMP6RCVD		43
#define COLUMN_TCPFRAGMENTSSENT		44
#define COLUMN_TCPFRAGMENTSRCVD		45
#define COLUMN_UDPFRAGMENTSSENT		46
#define COLUMN_UDPFRAGMENTSRCVD		47
#define COLUMN_ICMPFRAGMENTSSENT	48
#define COLUMN_ICMPFRAGMENTSRCVD	49
#define COLUMN_ICMP6FRAGMENTSSENT	50
#define COLUMN_ICMP6FRAGMENTSRCVD	51
#define COLUMN_TOTCONTACTEDSENTPEERS	52
#define COLUMN_TOTCONTACTEDRCVDPEERS	53
#define COLUMN_CONTACTEDSENTPEERS	54
#define COLUMN_CONTACTEDRCVDPEERS	55
#define COLUMN_CONTACTEDROUTERS		56
// #endif
// #ifndef NTOP_ENUMS_H
#define NTOP_ENUMS_H

/*
 * enums for column ntopSerialType (uguali a
 */
#define NTOPSERIALTYPE_UNKNOWN		0
#define NTOPSERIALTYPE_ETHSERIAL	1
#define NTOPSERIALTYPE_IPV4SERIAL	2
#define NTOPSERIALTYPE_IPV6SERIAL	3
#define NTOPSERIALTYPE_FCSERIAL		4
#define INITIALNUMBEROFHOST             256
/***********************************************************/
// #endif
// #endif /* NTOP_H */




/*
 * Static variables
 */
#ifdef CFG_MULTITHREADED
static pthread_t snmpThreadId;
static PthreadMutex snmpMutex;
#endif

static int actual_deviceId = 0, pluginActive = 0, everInitialized = 0;
static HostTraffic *my_el;
static oid ntopTable_oid[] = { 1, 3, 6, 1, 4, 1, 30000, 1 };
static u_char snmpDebug = 0;
static int maxNumberOfHost;
static int numberOfHost;
static HostTraffic** arrayOfHost;

/*
 * Plugin functions
 */
static void simplehandlePluginHostCreationDeletion (HostTraffic * el,
						    u_short deviceId,
						    u_char hostCreation);
static void initData ();
static void resetData ();
static void addHost (HostTraffic * el);
static void removeHost (HostTraffic * el);
static HostTraffic *searchHostByOid (oid *);
static HostTraffic **getNextHostByOid (oid * reqoid);
static HostTraffic *getFirstHostByOid ();
static oid* create_oid(HostTraffic* el);
static int compare_oid(oid* el1, oid* el2);
static int compare_hostTraffic(const void* host1,const void* host2);
static int compare_oidWithHost(const void* requestoid,const void* host1);
static oid* createAnswer(int column,HostTraffic* el);

/***************************************************************/

/*
 * Utils function to code/decode oid etc etc
 */
static int getHostSerialFromIndex (netsnmp_table_request_info *
				   table_info, HostSerial * serial);

static void processRequest (netsnmp_table_request_info * table_info,
			    netsnmp_variable_list * var,
			    HostTraffic * traffic);
static int  getCounter64(Counter c, struct counter64 *c64);

static oid* encodeEth(HostTraffic* el);
static oid* encodeIpv4(HostTraffic* el);
static oid* encodeIpv6(HostTraffic* el);
static oid* encodeFc(HostTraffic* el);
#endif /* HAVE_SNMP */


static int initSnmpFunct (void);
static void termSnmpFunct (u_char);
static void handleSnmpHTTPrequest (char *url);

/*
 * Agent functions
 */
static void start_agent (void);
static void *snmpAgentLoop (void *notUsed _UNUSED_);
static void init_ntop_snmp (void);
static void initialize_table_ntopTable (void);
static void simplehandlePluginHostCreationDeletion(HostTraffic * el,
						   u_short deviceId,
						   u_char hostCreation);

static PluginInfo snmpPluginInfo[] = {
  {
   VERSION,			/* current ntop version */
   "snmpPlugin",
   "This plugin is used to monitor host traffic using the SNMP protocol.",
   "0.1",			/* version */
   "<a href=mailto:fuscof@cli.di.unipi.it>F.Fusco</a><br><a href=mailto:giardina@cli.di.unipi.it>G.Giardina</a>",
   "snmpPlugin",
   0,				/* Not active by default */
   1,				/* Inactive setup */
   initSnmpFunct,		/* InitFunc */
   termSnmpFunct,		/* TermFunc */
   NULL,			/* PluginFunc */
   handleSnmpHTTPrequest,
   simplehandlePluginHostCreationDeletion,	/* host creation/deletion handle */
   NULL,			/* no capture */
   NULL				/* no status */
   }
};

/*
 * Plugin entry fctn
 */
#ifdef MAKE_STATIC_PLUGIN
PluginInfo *
snmpPluginEntryFctn (void)
{
#else
PluginInfo *
PluginEntryFctn (void)
{
#endif
  traceEvent (CONST_TRACE_ALWAYSDISPLAY,
	      "SNMP: Welcome to %s. (C) 2004 by F.Fusco and G.Giardina",
	      snmpPluginInfo->pluginName);
  return (snmpPluginInfo);
}

#ifdef HAVE_SNMP

static Netsnmp_Node_Handler ntopTable_handler;

/*
 ****************************** */

static int
initSnmpFunct (void)
{
  if(!everInitialized) {
    start_agent ();
    everInitialized = 1;
  }

  pluginActive = 1;
  traceEvent (CONST_TRACE_ALWAYSDISPLAY, "SnmpPlugin: initializing agent ");
#ifdef CFG_MULTITHREADED
  createThread (&snmpThreadId, snmpAgentLoop, NULL);
  createMutex(&snmpMutex);
#endif
  return(0);
}

/*
 **************************************** */
static void
termSnmpFunct (u_char termNtop /* 0=term plugin, 1=term ntop */)
{
  traceEvent (CONST_TRACE_ALWAYSDISPLAY,
	      "SnmpPlugin: terminating snmp (snmp_shutdown) ");
#ifdef CFG_MULTITHREADED
  if(pluginActive){
    killThread(&snmpThreadId);
    deleteMutex(&snmpMutex);
  }
#endif
  traceEvent (CONST_TRACE_INFO,
	      "SnmpPlugin: Thanks for using ntop snmpPlugin");
  traceEvent (CONST_TRACE_ALWAYSDISPLAY, "SnmpPlugin: Done");
  pluginActive = 0;

  if(termNtop)
    snmp_shutdown(AGENT_NAME);
}


/*
 **************************************** */
static void
handleSnmpHTTPrequest (char *_url)
{
  sendHTTPHeader (FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader ("snmpPlugin", NULL, 0);
  printFlagedWarning ("Work in progress. Read plugins/README.SNMP");
  printHTMLtrailer ();
}

/*
 *  When host is added to ntop hash it store a pointer of that host in the data strucuture.
 */
static void simplehandlePluginHostCreationDeletion (HostTraffic * el, u_short deviceId,
						    u_char hostCreation){
  if (hostCreation == 1){
    switch (el->hostSerial.serialType){
    case SERIAL_MAC:
      if(snmpDebug)
	traceEvent (CONST_TRACE_ALWAYSDISPLAY,
		    "Added host %s [deviceID =  %d, vlanid = %d(%d)]",
		    el->ethAddressString, deviceId,
		    el->hostSerial.value.ethSerial.vlanId, el->vlanId);

      break;
    case SERIAL_IPV4:
      if(snmpDebug)
	traceEvent (CONST_TRACE_ALWAYSDISPLAY,
		    "Added host %s [deviceID =  %d, vlanid = %d(%d)]",
		    el->hostNumIpAddress, deviceId,
		    el->hostSerial.value.ipSerial.vlanId, el->vlanId);
      if (my_el == NULL)
        my_el = el;

      break;
    }
    accessMutex(&snmpMutex,"add host");
    addHost(el);
    releaseMutex(&snmpMutex);
  }else{
    accessMutex(&snmpMutex,"remove host");
    removeHost(el);
    if(snmpDebug)  traceEvent(CONST_TRACE_ALWAYSDISPLAY,"Removed Host");
    releaseMutex(&snmpMutex);
  }
}

static void
start_agent ()
{
  snmp_enable_stderrlog ();

  /* If we're an AgentX subagent...  */
  if (AGENT_ISSUBAGENT)
    {
      /* ...make us an AgentX client.  */
      netsnmp_ds_set_boolean (NETSNMP_DS_APPLICATION_ID,
			      NETSNMP_DS_AGENT_ROLE, 1);
    }
  init_agent (AGENT_NAME);

  init_ntop_snmp ();

  /* `yourappname' will be used to read yourappname.conf files.  */
  init_snmp (AGENT_NAME);

  /* If we're going to be a SNMP master agent...  */
  if (!AGENT_ISSUBAGENT)
    init_master_agent ();	/* Listen on default port (161).  */

}

#ifdef CFG_MULTITHREADED
static void *
snmpAgentLoop (void *notUsed _UNUSED_)
{
  while (pluginActive)
    {
      agent_check_and_process (1);	/* 0 == don't block */
      if(snmpDebug) traceEvent (CONST_TRACE_ALWAYSDISPLAY, "snmpAgentLoop()");
    }

  return (NULL);
}
#endif

static int
getHostSerialFromIndex (netsnmp_table_request_info * table_info,
			HostSerial * serial)
{
  int octet_data_length;
  int serial_type;
  int actual_device;
  int vanid;
  netsnmp_variable_list *tmp;
  HostAddr *dst;

  uint32_t mod_value[4];
  char etherbuf[LEN_ETHERNET_ADDRESS_DISPLAY];
  char *ethAddr;
  char etherbuf1[LEN_ETHERNET_ADDRESS_DISPLAY];
  char *ethAddr1;

  char display_buffer[20];
  int i;

  if (table_info->indexes == NULL)
    return -1;

  tmp = table_info->indexes;

  // get serial_type
  serial_type = *(tmp->val.integer);
  tmp = tmp->next_variable;

  // get actual_device
  actual_device = *(tmp->val.integer);
  tmp = tmp->next_variable;

  //get ntopVanid (vlan e vsan)
  vanid = *(tmp->val.integer);
  tmp = tmp->next_variable;

  // take Serial and check lenght
  octet_data_length = tmp->val_len;

  // Ok, I've read all the necessary to build my HostSerial
  serial->serialType = serial_type;

  if(snmpDebug)
    traceEvent (CONST_TRACE_ALWAYSDISPLAY,
		"Processing request [serial =%d, device = %d, valore = ",
		serial_type, actual_device);

  switch (serial_type)
    {

    case SERIAL_NONE:
      if(snmpDebug) traceEvent (CONST_TRACE_ALWAYSDISPLAY, "No serial_type specified");
      return -1;
      break;

    case SERIAL_MAC:
      if (octet_data_length != LEN_ETHERNET_ADDRESS)
	return -1;

      memcpy (serial->value.ethSerial.ethAddress, tmp->val.string,octet_data_length);
      serial->value.ethSerial.vlanId = vanid;

      ethAddr = etheraddr_string (serial->value.ethSerial.ethAddress, etherbuf);
      if(snmpDebug) traceEvent (CONST_TRACE_ALWAYSDISPLAY, "The value is %s \n", ethAddr);

      break;

    case SERIAL_IPV4:
      if (octet_data_length != 4)
	return -1;
      serial->value.ipSerial.ipAddress.hostFamily = AF_INET;
      serial->value.ipSerial.vlanId = vanid;

      addrput (AF_INET, &(serial->value.ipSerial.ipAddress), tmp->val.string);
      if(snmpDebug)
	traceEvent (CONST_TRACE_ALWAYSDISPLAY, "The value is %s \n",
		    inet_ntop (AF_INET,&(serial->value.ipSerial.ipAddress.Ip4Address), display_buffer, 20));
      mod_value[0] = htonl (serial->value.ipSerial.ipAddress.Ip4Address.s_addr);
      addrput (AF_INET, &(serial->value.ipSerial.ipAddress), &mod_value);

      break;

    case SERIAL_IPV6:
      if (octet_data_length != 16)
	return -1;
      serial->value.ipSerial.ipAddress.hostFamily = AF_INET6;
      serial->value.ipSerial.vlanId = vanid;

      addrput (AF_INET6, &(serial->value.ipSerial.ipAddress), tmp->val.string);
      if(snmpDebug)
	traceEvent (CONST_TRACE_ALWAYSDISPLAY, "The value is %s \n",
		    inet_ntop (AF_INET6,&(serial->value.ipSerial.ipAddress.Ip6Address), display_buffer, 20));
      for (i=0;i<4;i++){
	mod_value[i] = htonl (serial->value.ipSerial.ipAddress.Ip6Address.s6_addr32[i]);
      }
      addrput (AF_INET, &(serial->value.ipSerial.ipAddress), &mod_value);

      break;

    case SERIAL_FC:
      return -1;
      break;
    defaults:return -1;	// wrong
    }

  return 1;
}

static compare_oidWithHost(const void* reqoid, const void* analyzingHost){

  oid* requestoid = *((oid**)reqoid);
  oid* analyzingOid = create_oid(*(HostTraffic**)analyzingHost);
  int i;
  int limit;
  if (requestoid[0] == 1)
    limit = 10;
  else if(requestoid[0] == 2)
    limit = 8;
  else if(requestoid[0] == 3)
    limit = 20;
  else limit = 7;

  for(i = 0;i<limit; i++){
    //   traceEvent(CONST_TRACE_ALWAYSDISPLAY,"%d,%d",requestoid[i],analyzingOid[i]);
    if(requestoid[i] < analyzingOid [i]){
      free(analyzingOid);
      return -1;
    }
    else if(requestoid[i] > analyzingOid[i]){
      free(analyzingOid);
      return 1;
    }
  }
  free(analyzingOid);
  return 0;
}

static int compare_oid(oid* analize1, oid* analize2){

    int i;
    int limit;

  if (analize1[0] == 1)
    limit = 10;
  else if(analize1[0] == 2)
    limit = 8;
  else if(analize1[0] == 3)
    limit = 20;
  else limit = 7;


  for(i = 0;i<limit; i++){
    //  traceEvent(CONST_TRACE_ALWAYSDISPLAY,"%d,%d",analize1[i],eanalize2[i]);
    if(analize1[i] < analize2[i])
      return -1;
    else if(analize1[i] > analize2[i])
      return 1;
  }
  return 0;
}
static int compare_hostTraffic(const void* analizeHost1, const void* analizeHost2){

  int i;
  oid * first= create_oid(*(HostTraffic**)analizeHost1);
  oid* second = create_oid(*(HostTraffic**)analizeHost2);
  i = compare_oid(first,second);
  free(first);
  free(second);
  return i;
}
static oid* create_oid(HostTraffic* el){
  oid* tmpoid;
  int numberOfOid;
  oid* ptr;
  oid* tmp;
  int i;
  int vlan;

  // traceEvent(CONST_TRACE_ALWAYSDISPLAY,"Dentro create_oid");
  if(el == NULL) {
    if(snmpDebug) traceEvent(CONST_TRACE_ALWAYSDISPLAY,"You give me a null pointer");
    return(NULL);
  }

  if (el->hostSerial.serialType == 1){
    numberOfOid = 7;
    vlan = el->hostSerial.value.ethSerial.vlanId;
  }else if(el->hostSerial.serialType == 2){
    numberOfOid = 5;
    vlan =  el->hostSerial.value.ipSerial.vlanId;
  }else if(el->hostSerial.serialType == 3){
    numberOfOid = 17;
    vlan =  el->hostSerial.value.ipSerial.vlanId;
  }else{
    numberOfOid = 4;
    vlan =  el->hostSerial.value.fcSerial.vsanId;
  }
  ptr=tmpoid=malloc((numberOfOid+3)*sizeof(oid));
  tmpoid[0]=el->hostSerial.serialType;
  tmpoid[1]=actual_deviceId;
  tmpoid[2]=vlan;
  ptr+=3;
  // traceEvent(CONST_TRACE_ALWAYSDISPLAY,"Ho allocato la memoria");
  if(tmpoid == NULL) {
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,"failed malloc");
    return(NULL);
  }
  switch (el->hostSerial.serialType){
  case SERIAL_MAC:
    tmp = encodeEth(el);
    break;
  case SERIAL_IPV4:
    tmp = encodeIpv4(el);
    break;
  case SERIAL_IPV6:
    tmp = encodeIpv6(el);
    break;
  case SERIAL_FC:
    tmp = encodeFc(el);
    break;
  default:
    return NULL;
  }
  // traceEvent(CONST_TRACE_ALWAYSDISPLAY,"ho ricevuto oid");
  memcpy(ptr,tmp,numberOfOid*sizeof(oid));
  free(tmp);
  /*  for(i=0;i<numberOfOid+3;i++)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,"tmpoid[%d]=%d",i,tmpoid[i]);*/
  return tmpoid;

}

static void addHost(HostTraffic* el){

  HostTraffic** tmp = arrayOfHost;
  int i=0;

  if(numberOfHost == maxNumberOfHost){
    maxNumberOfHost  +=INITIALNUMBEROFHOST;
    tmp = malloc(maxNumberOfHost*sizeof(void*));
    memcpy(tmp,arrayOfHost,numberOfHost*sizeof(void*));
    free(arrayOfHost);
    arrayOfHost= tmp;
  }
  while(i<numberOfHost && compare_hostTraffic(&el,tmp)>=0){
    tmp++;
    i++;
  }

  if(i != numberOfHost)
    memmove(tmp+1,tmp,(arrayOfHost+numberOfHost-tmp)*sizeof(HostTraffic*));

  *tmp=el;
  numberOfHost++;


  if(snmpDebug) {
    for(i=0;i<numberOfHost;i++)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,"Host=%s",arrayOfHost[i]->hostNumIpAddress);
  }

}

static void removeHost(HostTraffic* el){

  HostTraffic** tmp;
  void* ptr;
  tmp = (HostTraffic**)bsearch(&el,arrayOfHost,numberOfHost,sizeof(HostTraffic*),compare_hostTraffic);
  if(tmp != NULL){
    ptr=*tmp;

    if(snmpDebug) {
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,"Removing=%s",((HostTraffic*)ptr)->hostNumIpAddress);
      traceEvent(CONST_TRACE_ALWAYSDISPLAY,"Moving %d elements",(arrayOfHost+numberOfHost-1-tmp));
    }
    memmove(tmp,tmp+1,(arrayOfHost+numberOfHost-1-tmp)*sizeof(HostTraffic*));
  }
  numberOfHost--;
}

static void resetData(){
  free(arrayOfHost);
  arrayOfHost = NULL;
}

static void initData(){
  numberOfHost = 0;
  maxNumberOfHost = INITIALNUMBEROFHOST;
  arrayOfHost = malloc(maxNumberOfHost*sizeof(HostTraffic*));
}

static oid* encodeIpv4(HostTraffic* el){
  oid* tmpoid = malloc(sizeof(oid)*5);
  int i;
  u_int8_t* buf;
  u_int32_t addr =  htonl(el->hostSerial.value.ipSerial.ipAddress.Ip4Address.s_addr);
  buf = (u_int8_t*) &addr;
  tmpoid[0]=4;
  for(i=1;i<5;i++)
    tmpoid[i]=buf[i-1];
  return tmpoid;
}

static oid* encodeIpv6(HostTraffic* el){
  oid* tmpoid = malloc(sizeof(oid)*17);
  int i,j;
  u_int32_t buf[4];
  u_int8_t* ptr;
  for(i=0;i<4;i++)
    buf[i] =  htonl(el->hostSerial.value.ipSerial.ipAddress.Ip6Address.s6_addr32[i]);
  tmpoid[0]=17;
  for(i=0;i<4;i++){
    ptr = (u_int8_t*) &buf[i];
    for(j=0;j<4;j++)
      tmpoid[(4*i)+1+j]=ptr[j];
  }
  return tmpoid;
}

static oid* encodeEth(HostTraffic* el){
  oid* tmpoid = malloc(sizeof(oid)*7);
  int i;
  u_int8_t* buf;
  buf = (u_int8_t*) &(el->hostSerial.value.ethSerial.ethAddress);
  tmpoid[0]=6;
  for(i=1;i<7;i++)
    tmpoid[i]=buf[i-1];

  return tmpoid;
}
static oid* encodeFc(HostTraffic* el){
  oid* tmpoid = malloc(sizeof(oid)*4);
  int i;
  u_int8_t* buf;
  tmpoid[0] = 3;
  tmpoid[1] = el->hostSerial.value.fcSerial.fcAddress.domain;
  tmpoid[2] = el->hostSerial.value.fcSerial.fcAddress.area;
  tmpoid[3] = el->hostSerial.value.fcSerial.fcAddress.port;

  return tmpoid;
}

static oid* createAnswer(int column,HostTraffic* el){
  oid* tmp;
  oid* resoid;
  int numberOfOid,i,j;

  tmp = create_oid(el);
  /* traceEvent (CONST_TRACE_ALWAYSDISPLAY, "Ho creato l'oid");*/
  if (tmp[0] == 1)
    numberOfOid = 10;
  else if(tmp[0] == 2)
    numberOfOid = 8;
  else if(tmp[0] == 3)
    numberOfOid = 20;
  else numberOfOid = 7;

  if(snmpDebug)
    traceEvent (CONST_TRACE_ALWAYSDISPLAY,
		"SerialType %d, malloc for %d oid",tmp[0],numberOfOid+OID_LENGTH(ntopTable_oid)+2);

  resoid = malloc((numberOfOid+OID_LENGTH(ntopTable_oid)+2)*sizeof(oid));
  for(i = 0;i<OID_LENGTH(ntopTable_oid);i++)
    resoid[i]=ntopTable_oid[i];

  resoid[OID_LENGTH(ntopTable_oid)]=1;//is ntopEntry
  resoid[OID_LENGTH(ntopTable_oid)+1]=column;

  for(i = 10,j=0;i<numberOfOid+OID_LENGTH(ntopTable_oid)+2;i++,j++){
    resoid[i]=tmp[j];
  }
  /*
  for(i = 0;i<numberOfOid+OID_LENGTH(ntopTable_oid)+2;i++)
    traceEvent(CONST_TRACE_ALWAYSDISPLAY,"resoid[%d]=%d",i,resoid[i]);
  */
  free(tmp);
  return resoid;
}

/**************************************************************/
static HostTraffic *
getFirstHostByOid ()
{
   return *arrayOfHost;
}

/*****************************************************************/
static HostTraffic **
getNextHostByOid (oid * reqoid)
{
  return  (HostTraffic**) bsearch(&reqoid,arrayOfHost,numberOfHost,sizeof(HostTraffic*),compare_oidWithHost);
}

/*********************************************************************/
static int  getCounter64(Counter c, struct counter64 *c64){
  c64->low = c;
  c64->high = c >> 32;
  return 1;
}

/***************************************************************************************/
static void
processRequest (netsnmp_table_request_info * table_info,
		netsnmp_variable_list * var, HostTraffic * traffic)
{
  struct counter64 result;
  int result_size = sizeof(struct counter64);
  int intresult;
  char *cp;
  int size;

  if (table_info != NULL && traffic != NULL)
    {
      switch (table_info->colnum)
	{
	case COLUMN_NTOPSERIALTYPE:
	  intresult = traffic->hostSerial.serialType;
	  snmp_set_var_typed_value (var, ASN_INTEGER,
				    (u_char *) & (intresult), sizeof (intresult));
	  break;

	case COLUMN_NTOPACTUALDEVICE:
	  snmp_set_var_typed_value (var, ASN_INTEGER,
				    (u_char *) & (actual_deviceId),
				    sizeof (actual_deviceId));

	  break;

	case COLUMN_NTOPVANID:
	  switch(traffic->hostSerial.serialType){
	  case SERIAL_MAC:
	    intresult = traffic->hostSerial.value.ethSerial.vlanId;
	    break;
	  case SERIAL_IPV4:
	    intresult = traffic->hostSerial.value.ipSerial.vlanId;
	    break;
	  case SERIAL_IPV6:
	    intresult = traffic->hostSerial.value.ipSerial.vlanId;
	    break;
	  case SERIAL_FC:
	    intresult = traffic->hostSerial.value.fcSerial.vsanId;
	    break;
	  }

	  snmp_set_var_typed_value(var, ASN_INTEGER,
				   (u_char *) &intresult
				   , sizeof(intresult));
	  break;

	case COLUMN_NTOPSERIAL:
	  /*TODO: ip addr are printed in host byte order, please correct*/
	  switch (traffic->hostSerial.serialType)
	    {
	    case SERIAL_MAC:
	      cp = traffic->hostSerial.value.ethSerial.ethAddress;
	      size = 6;
	      break;
	    case SERIAL_IPV4:
	      cp = (char *)&traffic->hostSerial.value.ipSerial.ipAddress.Ip4Address.s_addr;
	      size = 4;
	      break;
	    case SERIAL_IPV6:
	      cp =(char *)&traffic->hostSerial.value.ipSerial.ipAddress.Ip6Address.s6_addr32;
	      size = 16;
	      break;
	    case SERIAL_FC:
	      /*TODO*/
	      size = LEN_FC_ADDRESS_DISPLAY;
	      break;
	    }

	  snmp_set_var_typed_value (var, ASN_OCTET_STR, (u_char *) cp, size);

	  break;

	case COLUMN_HOSTRESOLVEDNAME:
	  snmp_set_var_typed_value(var, ASN_OCTET_STR,
				   (u_char *) traffic->hostResolvedName
				   ,MAX_LEN_SYM_HOST_NAME
				   );
	  break;

	case COLUMN_FINGERPRINT:
	  snmp_set_var_typed_value(var, ASN_OCTET_STR,
				   (u_char *)(traffic->fingerprint == NULL ? "" : traffic->fingerprint),
				   (traffic->fingerprint == NULL ? : strlen(traffic->fingerprint)));
	  break;

	case COLUMN_PKTSENT:
	  getCounter64(traffic->pktSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTRCVD:
	  getCounter64(traffic->pktRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTSENTSESSION:
	  getCounter64(traffic->pktSentSession.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTRCVDSESSION:
	  getCounter64(traffic->pktRcvdSession.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTDUPLICATEDACKSENT:
	  getCounter64(traffic->pktDuplicatedAckSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTDUPLICATEDACKRCVD:
	  getCounter64(traffic->pktDuplicatedAckRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTBROADCASTSENT:
	  getCounter64(traffic->pktBroadcastSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESBROADCASTSENT:
	  getCounter64(traffic->bytesBroadcastSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTMULTICASTSENT:
	  getCounter64(traffic->pktMulticastSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESMULTICASTSENT:
	  getCounter64(traffic->bytesMulticastSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_PKTMULTICASTRCVD:
	  getCounter64(traffic->pktMulticastRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESMULTICASTRCVD:
	  getCounter64(traffic->bytesMulticastRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESSENT:
	  getCounter64(traffic->bytesSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESSENTLOC:
	  getCounter64(traffic->bytesSentLoc.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESSENTREM:
	  getCounter64(traffic->bytesSentRem.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESSENTSESSION:
	  getCounter64(traffic->bytesSentSession.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESRCVD:
	  getCounter64(traffic->bytesRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESRCVDLOC:
	  getCounter64(traffic->bytesRcvdLoc.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESRCVDFROMREM:
	  getCounter64(traffic->bytesRcvdFromRem.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_BYTESRCVDSESSION:
	  getCounter64(traffic->bytesRcvdSession.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_NUMHOSTSESSIONS:
	  getCounter64(traffic->numHostSessions,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_IPBYTESSENT:
	  getCounter64(traffic->ipBytesSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_IPBYTESRCVD:
	  getCounter64(traffic->ipBytesRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_IPV6SENT:
	  getCounter64(traffic->ipv6Sent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_IPV6RCVD:
	  getCounter64(traffic->ipv6Rcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TCPSENTLOC:
	  getCounter64(traffic->tcpSentLoc.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TCPSENTREM:
	  getCounter64(traffic->tcpSentRem.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_UDPSENTLOC:
	  getCounter64(traffic->udpSentLoc.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_UDPSENTREM:
	  getCounter64(traffic->udpSentRem.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMPSENT:
	  getCounter64(traffic->icmpSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMP6SENT:
	  getCounter64(traffic->icmp6Sent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TCPRCVDLOC:
	  getCounter64(traffic->tcpRcvdLoc.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TCPRCVDFROMREM:
	  getCounter64(traffic->tcpRcvdFromRem.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_UDPRCVDLOC:
	  getCounter64(traffic->udpRcvdLoc.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_UDPRCVDFROMREM:
	  getCounter64(traffic->udpRcvdFromRem.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMPRCVD:
	  getCounter64(traffic->icmpRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMP6RCVD:
	  getCounter64(traffic->icmp6Rcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TCPFRAGMENTSSENT:
	  getCounter64(traffic->tcpFragmentsSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TCPFRAGMENTSRCVD:
	  getCounter64(traffic->tcpFragmentsRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_UDPFRAGMENTSSENT:
	  getCounter64(traffic->udpFragmentsSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_UDPFRAGMENTSRCVD:
	  getCounter64(traffic->udpFragmentsRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMPFRAGMENTSSENT:
	  getCounter64( traffic->icmpFragmentsSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMPFRAGMENTSRCVD:
	  getCounter64(traffic->icmpFragmentsRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMP6FRAGMENTSSENT:
	  getCounter64(traffic->icmp6FragmentsSent.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_ICMP6FRAGMENTSRCVD:
	  getCounter64(traffic->icmp6FragmentsRcvd.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TOTCONTACTEDSENTPEERS:
	  getCounter64(traffic->totContactedSentPeers,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_TOTCONTACTEDRCVDPEERS:
	  getCounter64(traffic->totContactedRcvdPeers,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_CONTACTEDSENTPEERS:
	  getCounter64(traffic->contactedSentPeers.value.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_CONTACTEDRCVDPEERS:
	  getCounter64(traffic->contactedRcvdPeers.value.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	case COLUMN_CONTACTEDROUTERS:
	  getCounter64(traffic->contactedRouters.value.value,&result);
	  snmp_set_var_typed_value(var, ASN_COUNTER64,
				   (u_char *) &result
				   , sizeof(result)
				   );
	  break;

	default:
	  snmp_log (LOG_ERR,
		    "problem encountered in ntopTable_handler: unknown column\n");
	}
    }
}

/*  *********************************************************************** */

static void initialize_table_ntopTable (void)
{
  // static oid ntopTable_oid[] = { 1, 3, 6, 1, 4, 1, 30000, 1 };
  netsnmp_table_registration_info *table_info;
  netsnmp_handler_registration *my_handler;



  /** create the table registration information structures */
  table_info = SNMP_MALLOC_TYPEDEF (netsnmp_table_registration_info);


  /* Read only table */
  my_handler = netsnmp_create_handler_registration ("ntopTable",
						    ntopTable_handler,
						    ntopTable_oid,
						    OID_LENGTH
						    (ntopTable_oid),
						    HANDLER_CAN_RONLY);

  if (!my_handler || !table_info)
    {
      snmp_log (LOG_ERR, "malloc failed in initialize_table_ntopTable");
      return;
    }

  /* Setting up the table's definition */
  netsnmp_table_helper_add_indexes (table_info,
				    ASN_INTEGER,       /* index: ntopSerialType */
				    ASN_INTEGER,       /* index: ntopActualDevice */
				    ASN_INTEGER,       /* index: ntopVanId */
				    ASN_OCTET_STR,     /* index: ntopSerial */
				    0);

  /** Define the minimum and maximum accessible columns.*/
  table_info->min_column = 1;
  table_info->max_column = 56;

  netsnmp_register_table (my_handler, table_info);
  initData();
}

/** Initializes the ntop module */
static void init_ntop_snmp (void)
{
  /** here we initialize all the tables we're planning on supporting */
  initialize_table_ntopTable ();
}


/** handles requests for the ntopTable table, if anything else needs to be done */
int
ntopTable_handler (netsnmp_mib_handler * handler,
		   netsnmp_handler_registration * reginfo,
		   netsnmp_agent_request_info * reqinfo,
		   netsnmp_request_info * requests)
{

  netsnmp_request_info *request;
  netsnmp_table_request_info *table_info;
  netsnmp_variable_list *var;

  HostSerial serial;
  HostTraffic *traffic = NULL;
  HostTraffic** resultOfResearch = NULL;
  oid* resoid;
  oid* tmp;
  int numberOfOid;
  int i,j;
  int req_length;

  for (request = requests; request; request = request->next)
    {
      var = request->requestvb;

      if (request->processed != 0)
	continue;

		/** extracts the information about the table from the request
		 *  Now I can use
		 *  -table_info->indexes
		 *  -table_info->column
		 */
      table_info = netsnmp_extract_table_info (request);

      if (table_info == NULL){
	continue;
      }

      switch (reqinfo->mode){

	case MODE_GET:
	  if (getHostSerialFromIndex (table_info, &serial) > 0){
	    traffic = findHostBySerial (serial, actual_deviceId);
	  }
	  if (traffic == NULL){
	    netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
	    return SNMP_NOSUCHOBJECT;
	  } else {
	    processRequest (table_info, var, traffic);
	  }
	  break;

	case MODE_GETNEXT:
	  if(snmpDebug) traceEvent(CONST_TRACE_ALWAYSDISPLAY,"There are %d host ",numberOfHost);
	  if(numberOfHost == 0){
	    netsnmp_set_request_error (reqinfo, request, SNMP_NOSUCHOBJECT);
	    return SNMP_NOSUCHOBJECT;
	  }

	  req_length = sizeof(ntopTable_oid)/sizeof(oid);
	  // No index specified

	  accessMutex(&snmpMutex,"Reading");
	  if (var->name_length <= req_length + 2){
	    if(snmpDebug) traceEvent (CONST_TRACE_ALWAYSDISPLAY, "No Index specified, I take the first");
	    traffic = getFirstHostByOid ();
	    if(snmpDebug) traceEvent (CONST_TRACE_ALWAYSDISPLAY, "first element taken");
	    if (traffic == NULL){
	      netsnmp_set_request_error (reqinfo, request,
					 SNMP_NOSUCHOBJECT);
	      releaseMutex(&snmpMutex);
	      return SNMP_NOSUCHOBJECT;
	    }
	  }else{
	    //Index specified
	    if(snmpDebug) traceEvent (CONST_TRACE_ALWAYSDISPLAY, "Index specified, I must find the next");
	    resultOfResearch = getNextHostByOid((var->name)+OID_LENGTH(ntopTable_oid)+2);
	    if(resultOfResearch == NULL){
	      netsnmp_set_request_error (reqinfo, request,
					 SNMP_NOSUCHOBJECT);
	      releaseMutex(&snmpMutex);
	      return SNMP_NOSUCHOBJECT;
	    }
	    if(resultOfResearch==(arrayOfHost+numberOfHost-1) && table_info->colnum == table_info->reg_info->max_column ){
	      if(snmpDebug) traceEvent(CONST_TRACE_ALWAYSDISPLAY,"You have request the last element of the last column");
	      netsnmp_set_request_error (reqinfo, request,
					 SNMP_NOSUCHOBJECT);

	      releaseMutex(&snmpMutex);
	      return SNMP_NOSUCHOBJECT;
	    }
	    if(resultOfResearch==(arrayOfHost+numberOfHost-1)){
	      if(snmpDebug) traceEvent(CONST_TRACE_ALWAYSDISPLAY,"You have request last element");
	      traffic = getFirstHostByOid();
	      table_info->colnum++;
	    }else{
	      traffic = *(resultOfResearch+1);
	    }
	  }
	  releaseMutex(&snmpMutex);
	  if(snmpDebug)
	    traceEvent (CONST_TRACE_ALWAYSDISPLAY,
			"Found host %s [deviceID =  %d, vlanid = %d(%d)]",
			traffic->hostNumIpAddress, 0,
			traffic->hostSerial.value.ipSerial.vlanId, traffic->vlanId);

	  resoid = createAnswer(table_info->colnum,traffic);

	  if(traffic->hostSerial.serialType == 1)
	    numberOfOid = 10;
	  else if(traffic->hostSerial.serialType == 2)
	    numberOfOid = 8;
	  else if(traffic->hostSerial.serialType == 3)
	    numberOfOid = 20;
	  else
	    numberOfOid = 8;

	  snmp_set_var_objid(var,resoid,numberOfOid+OID_LENGTH(ntopTable_oid)+2);
	  processRequest (table_info, var, traffic);
	  free(resoid);
      	  break;

      default:
	snmp_log (LOG_ERR,
		  "problem encountered in ntopTable_handler: unsupported mode\n");
      }
    }
  return SNMP_ERR_NOERROR;
}

#else /* !HAVE_SNMP */
static int initSnmpFunct (void) { return(0); }
static void termSnmpFunct (u_char termNtop /* 0=term plugin, 1=term ntop */) { ;} 

static void handleSnmpHTTPrequest (char *_url) {
  sendHTTPHeader (FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader ("snmpPlugin", NULL, 0);
  printFlagedWarning ("SNMP support disabled or not available");
  printHTMLtrailer ();
}

static void simplehandlePluginHostCreationDeletion(HostTraffic *el,
						   u_short deviceId,
						   u_char hostCreation) {
}

#endif
