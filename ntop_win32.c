/*
 *  Copyright (C) 1998-99 Luca Deri <deri@ntop.org>
 *                        Portions by Stefano Suin <stefano@ntop.org>
 *                      
 *  			  Centro SERRA, University of Pisa
 *  			  http://www.ntop.org/
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

#include <stdio.h>
#include <string.h>
#include <winsock2.h>

#include <winioctl.h>
#include "ntddndis.h"        // This defines the IOCTL constants.

#include "ntop.h"

extern char* intoa(struct in_addr addr);

extern char domainName[];
char *buildDate;

/*
extern char* device; 
extern int datalink;
extern unsigned int localnet, netmask;
*/

char* getNwBoardMacAddress(char *deviceName); /* forward */

ULONG GetHostIPAddr(); /* forward declaration */


#ifdef ORIGINAL_NTOP

TCHAR	       AdapterName[64];
FRAMEETH       ethernetFrame;
ULONG		   NameLength=64, FrameLength;
LPADAPTER	   Adapter;
LPPACKET       Packet;

/* ************************************************** */

typedef PVOID NDIS_HANDLE, *PNDIS_HANDLE;

#if 0
void initSniffer() {
  /* device = "eth"; */
  datalink = DLT_EN10MB;

	/* ****************** */
	
  PacketGetAdapterNames(AdapterName, &NameLength);

  Adapter = PacketOpenAdapter(AdapterName);
  if(Adapter == NULL) {
   traceEvent(TRACE_ERROR, "FATAL ERROR: please install MS NDIS 3.0 driver. Bye...\n");
    exit(-1);
  }
  PacketSetFilter(Adapter, NDIS_PACKET_TYPE_PROMISCUOUS);	
  Packet = PacketAllocatePacket();
  PacketInitPacket(Packet, (PVOID)(&ethernetFrame), sizeof(FRAMEETH));
}
#endif

/* ******************************************** */

void terminateSniffer() {
  PacketCloseAdapter(Adapter);
}

/* ********************************** */

void sniffSinglePacket(void(*pbuf_process)(u_char *unused, 
					   const struct pcap_pkthdr *h, 
					   const u_char *p)) 
{
  struct pcap_pkthdr hdr;
  static int numPkts = 0;

  PacketReceivePacket(Adapter, Packet, TRUE, &FrameLength);
  hdr.caplen = (u_int32)FrameLength;
  hdr.len    = (u_int32)FrameLength;

#ifdef WIN32_DEMO
  if(numPkts < MAX_NUM_PACKETS)
#endif
    pbuf_process(NULL, &hdr, (u_char*)&ethernetFrame);

  numPkts++;
}

#endif /* ORIGINAL_NTOP */

/* ************************************************** */

short isWinNT() {
  DWORD dwVersion;
  DWORD dwWindowsMajorVersion;

  dwVersion=GetVersion();
  dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
  if(!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4))
    return 1;
  else
    return 0;
}

/* ************************************************** */

void initWinsock32() {
  WORD wVersionRequested;
  WSADATA wsaData;
  int err; 

  wVersionRequested = MAKEWORD(2, 0); 
  err = WSAStartup( wVersionRequested, &wsaData );
  if( err != 0 ) {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */    
   traceEvent(TRACE_ERROR, "FATAL ERROR: unable to initialise Winsock 2.x.\n");
    exit(-1);
  }

  SIZE_BUF = 5 * 1024 * 1024; /* 5MB buffer */
  version = "1.3.2";
  author  = "Luca Deri <deri@ntop.org>";
  buildDate = "11/10/2000";

  if(isWinNT())
    osName = "WinNT/2K";
  else
    osName = "Win95/98";

#ifdef WIN32_DEMO
 traceEvent(TRACE_INFO, "\n-----------------------------------------------------------\n");
 traceEvent(TRACE_INFO, "WARNING: this application is a limited ntop version able to\n");
 traceEvent(TRACE_INFO, "capture up to %d packets. If you are interested\n", MAX_NUM_PACKETS);
 traceEvent(TRACE_INFO, "in the full version please have a look at the ntop\n");
 traceEvent(TRACE_INFO, "home page http://www.ntop.org/.\n");
 traceEvent(TRACE_INFO, "-----------------------------------------------------------\n\n");
#endif
}

/* ************************************************** */

void termWinsock32() {
  WSACleanup( );
  //terminateSniffer();
}
/* ************************************************** */


ULONG GetHostIPAddr () {
  char szLclHost [64];
  LPHOSTENT lpstHostent;
  SOCKADDR_IN stLclAddr;
  SOCKADDR_IN stRmtAddr;
  int nAddrSize = sizeof(SOCKADDR);
  SOCKET hSock;
  int nRet;
    
  /* Init local address (to zero) */
  stLclAddr.sin_addr.s_addr = INADDR_ANY;
    
  /* Get the local hostname */
  nRet = gethostname(szLclHost, 64); 
  if(nRet != SOCKET_ERROR) {
    /* Resolve hostname for local address */
    lpstHostent = gethostbyname((LPSTR)szLclHost);
    if(lpstHostent) {
      struct hostent *hp;

      stLclAddr.sin_addr.s_addr = *((u_long FAR*) (lpstHostent->h_addr));

      hp = (struct hostent*)gethostbyaddr((char*)&stLclAddr.sin_addr.s_addr, 4, AF_INET);
	  
      if(hp && (hp->h_name)) {
	char *dotp = (char*)hp->h_name;    
	int i;

	for(i=0; (dotp[i] != '\0') && (dotp[i] != '.'); i++)
	  ;

	if(dotp[i] == '.') strncpy(domainName, &dotp[i+1], sizeof(domainName));
      }
    }
  } 
    
  /* If still not resolved, then try second strategy */
  if(stLclAddr.sin_addr.s_addr == INADDR_ANY) {
    /* Get a UDP socket */
    hSock = socket(AF_INET, SOCK_DGRAM, 0);
    if(hSock != INVALID_SOCKET)  {
      /* Connect to arbitrary port and address (NOT loopback) */
      stRmtAddr.sin_family = AF_INET;
      stRmtAddr.sin_port   = htons(IPPORT_ECHO);
      stRmtAddr.sin_addr.s_addr = inet_addr("128.127.50.1");
      nRet = connect(hSock,
		     (LPSOCKADDR)&stRmtAddr,
		     sizeof(SOCKADDR));
      if(nRet != SOCKET_ERROR)
	/* Get local address */
	getsockname(hSock, 
		    (LPSOCKADDR)&stLclAddr, 
		    (int FAR*)&nAddrSize);
        
      closesocket(hSock);   /* we're done with the socket */
    }
  }

  /* Little/big endian crap... */
  stLclAddr.sin_addr.s_addr = ntohl(stLclAddr.sin_addr.s_addr);

  return (stLclAddr.sin_addr.s_addr);
}

/* **************************************
   
   	       WIN32 MULTITHREAD STUFF
   
   ************************************** */

int createThread(pthread_t *threadId,
		 void *(*__start_routine) (void *), char* userParm) {
  DWORD dwThreadId, dwThrdParam = 1; 

  (*threadId) = CreateThread(NULL, /* no security attributes */ 
			     0,            /* use default stack size */ 
			     (LPTHREAD_START_ROUTINE)__start_routine, /* thread function */ 
			     NULL, /* argument to thread function */ 
			     0,            /* use default creation flags */ 
			     &dwThreadId); /* returns the thread identifier */ 

  if(*threadId != NULL)
    return(1);
  else
    return(0);
}

/* ************************************ */

void killThread(pthread_t *threadId) {
  CloseHandle((HANDLE)*threadId);
}

/* ************************************ */

int createMutex(pthread_mutex_t *mutexId) {
  (*mutexId) = CreateMutex(NULL, FALSE, NULL);
  return(1);
}

/* ************************************ */

void deleteMutex(pthread_mutex_t *mutexId) {
  ReleaseMutex(*mutexId);
  CloseHandle(*mutexId);
}

/* ************************************ */

int _accessMutex(pthread_mutex_t *mutexId, char* where, 
		 char* fileName, int fileLine) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Locking 0x%X @ %s [%s:%d]\n", 
	     mutexId, where, fileName, fileLine);
#endif

  WaitForSingleObject(*mutexId, INFINITE);
  return(1);
}

/* ************************************ */

int _tryLockMutex(pthread_mutex_t *mutexId, char* where,
		 char* fileName, int fileLine) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Try to Lock 0x%X @ %s [%s:%d]\n",
	     mutexId, where, fileName, fileLine);
  fflush(stdout);
#endif
  
  if(WaitForSingleObject(*mutexId, 0) == WAIT_FAILED)
    return(0);
  else
    return(1);
}

/* ************************************ */

int _releaseMutex(pthread_mutex_t *mutexId, 
		  char* fileName, int fileLine) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Unlocking 0x%X [%s:%d]\n", 
	     mutexId, fileName, fileLine); 
#endif
  ReleaseMutex(*mutexId);
  return(1);
}

/* ************************************ */

int createCondvar(ConditionalVariable *condvarId) {
  condvarId->condVar = CreateEvent(NULL,  /* no security */
				   TRUE , /* auto-reset event (FALSE = single event, TRUE = broadcast) */
				   FALSE, /* non-signaled initially */
				   NULL); /* unnamed */
  InitializeCriticalSection(&condvarId->criticalSection);
  return(1);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  CloseHandle(condvarId->condVar);
  DeleteCriticalSection(&condvarId->criticalSection);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;
#ifdef DEBUG
 traceEvent(TRACE_INFO, "Wait (%x)...\n", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);
#ifdef DEBUG
 traceEvent(TRACE_INFO, "Got signal (%d)...\n", rc);
#endif
  return(rc);
}

/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId) {
#ifdef DEBUG
 traceEvent(TRACE_INFO, "Signaling (%x)...\n", condvarId->condVar);
#endif
  return((int)PulseEvent(condvarId->condVar));
}

/* ************************************ */

#if 0
void printAvailableInterfaces() {
  ULONG nameLength = 128;
  WCHAR adaptersName[128];
	
  PacketGetAdapterNames (adaptersName, &nameLength);

  if(isWinNT())
    {
      static char tmpString[128];
      int i, j;

      for(j=0, i=0; !((adaptersName[i] == 0) && (adaptersName[i+1] == 0)); i++) {
	if(adaptersName[i] != 0)
	  tmpString[j++] = adaptersName[i];
      }

      tmpString[j++] = 0;
      memcpy(adaptersName, tmpString, 128);
    }

  traceEvent(TRACE_INFO, "Available interfaces:\n%s\n", (char*)adaptersName);
}
#endif

/* ************************************ */

#define _PATH_NETWORKS	"networks"

#define	MAXALIASES	35

static char NETDB[] = _PATH_NETWORKS;
static FILE *netf = NULL;
static char line[BUFSIZ+1];
static struct netent net;
static char *net_aliases[MAXALIASES];
static char *any(char *, char *);

int _net_stayopen;

void
setnetent(f)
     int f;
{
  if(netf == NULL)
    netf = fopen(NETDB, "r" );
  else
    rewind(netf);
  _net_stayopen |= f;
}

void
endnetent()
{
  if(netf) {
    fclose(netf);
    netf = NULL;
  }
  _net_stayopen = 0;
}

static char *
any(cp, match)
     register char *cp;
     char *match;
{
  register char *mp, c;

  while (c = *cp) {
    for (mp = match; *mp; mp++)
      if(*mp == c)
	return (cp);
    cp++;
  }
  return ((char *)0);
}

u_int32_t
inet_network(const char *cp)
{
  register u_long val, base, n;
  register char c;
  u_long parts[4], *pp = parts;
  register int i;

 again:
  /*
   * Collect number up to ``.''.
   * Values are specified as for C:
   * 0x=hex, 0=octal, other=decimal.
   */
  val = 0; base = 10;
  /*
   * The 4.4BSD version of this file also accepts 'x__' as a hexa
   * number.  I don't think this is correct.  -- Uli
   */
  if(*cp == '0') {
    if(*++cp == 'x' || *cp == 'X')
      base = 16, cp++;
    else
      base = 8;
  }
  while ((c = *cp)) {
    if(isdigit(c)) {
      val = (val * base) + (c - '0');
      cp++;
      continue;
    }
    if(base == 16 && isxdigit(c)) {
      val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
      cp++;
      continue;
    }
    break;
  }
  if(*cp == '.') {
    if(pp >= parts + 4)
      return (INADDR_NONE);
    *pp++ = val, cp++;
    goto again;
  }
  if(*cp && !isspace(*cp))
    return (INADDR_NONE);
  *pp++ = val;
  n = pp - parts;
  if(n > 4)
    return (INADDR_NONE);
  for (val = 0, i = 0; i < (int)n; i++) {
    val <<= 8;
    val |= parts[i] & 0xff;
  }
  return (val);
}

struct netent *
getnetent()
{
  char *p;
  register char *cp, **q;

  if(netf == NULL && (netf = fopen(NETDB, "r" )) == NULL)
    return (NULL);
 again:
  p = fgets(line, BUFSIZ, netf);
  if(p == NULL)
    return (NULL);
  if(*p == '#')
    goto again;
  cp = any(p, "#\n");
  if(cp == NULL)
    goto again;
  *cp = '\0';
  net.n_name = p;
  cp = any(p, " \t");
  if(cp == NULL)
    goto again;
  *cp++ = '\0';
  while (*cp == ' ' || *cp == '\t')
    cp++;
  p = any(cp, " \t");
  if(p != NULL)
    *p++ = '\0';
  net.n_net = inet_network(cp);
  net.n_addrtype = AF_INET;
  q = net.n_aliases = net_aliases;
  if(p != NULL) 
    cp = p;
  while (cp && *cp) {
    if(*cp == ' ' || *cp == '\t') {
      cp++;
      continue;
    }
    if(q < &net_aliases[MAXALIASES - 1])
      *q++ = cp;
    cp = any(cp, " \t");
    if(cp != NULL)
      *cp++ = '\0';
  }
  *q = NULL;
  return (&net);
}

struct netent *getnetbyname(const char *name)
{
  register struct netent *p;
  register char **cp;

  setnetent(_net_stayopen);
  while (p = getnetent()) {
    if(strcmp(p->n_name, name) == 0)
      break;
    for (cp = p->n_aliases; *cp != 0; cp++)
      if(strcmp(*cp, name) == 0)
	goto found;
  }
 found:
  if(!_net_stayopen)
    endnetent();
  return (p);
}


/* Find the first bit set in I.  */
int ffs (int i) 
{
  static const unsigned char table[] =
  {
    0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
  };
  unsigned long int a;
  unsigned long int x = i & -i;

  a = x <= 0xffff ? (x <= 0xff ? 0 : 8) : (x <= 0xffffff ?  16 : 24);

  return table[x >> a] + a;
}

/* ****************************************************** */

int gettimeofday(struct timeval *tv, struct timezone *notUsed) {
  tv->tv_sec = time(NULL);
  tv->tv_usec = 0;
  return(0);
}

/* ****************************************************** */

int snprintf(char *string, size_t maxlen, const char *format, ...) {
  int ret=0;
  va_list args;
  
  va_start(args, format);
  vsprintf(string,format,args);
  va_end(args);
  return ret;
}

