/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
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
#include <process.h>
#include <tchar.h>
#include <winioctl.h>
#include "ntddndis.h"        // This defines the IOCTL constants.

#include "ntop.h"

extern char* intoa(struct in_addr addr);

extern char domainName[];
char *buildDate;
char _wdir[256];

/*
  extern char* myGlobals.device;
  extern int datalink;
  extern unsigned int localnet, netmask;
*/

char* getNwBoardMacAddress(char *deviceName); /* forward */

ULONG GetHostIPAddr(); /* forward declaration */

#define NTOP_SERVICE_STOPPED 1
#define NTOP_SHUTDOWN 2
#define NTOP_CLOSE 3
#define NTOP_LOGOFF 4

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
    traceEvent(TRACE_ERROR, "FATAL ERROR: unable to initialise Winsock 2.x.");
    exit(-1);
  }

  version = "2.1.52";
  author  = "Luca Deri <deri@ntop.org>";
  buildDate = "30/10/2002";

  if(!isWinNT()) {
    osName = "Win95/98/ME";
    strcpy(_wdir, ".");
  } else {
    osName = "WinNT/2K/XP";

		// Get the full path and filename of this program
	  if(GetModuleFileName( NULL, _wdir, sizeof(_wdir) ) == 0 ) {
		_wdir[0] = '\0';
	  } else {
		int i;

		for(i=strlen(_wdir)-1; i>0; i--)
		  if(_wdir[i] == '\\') {
		_wdir[i] = '\0';
		break;
		  }
	  }

	  /* traceEvent(TRACE_ERROR, "Wdir=%s", _wdir); */
  }

    
#ifdef WIN32_DEMO
  traceEvent(TRACE_INFO, "\n-----------------------------------------------------------");
  traceEvent(TRACE_INFO, "WARNING: this application is a limited ntop myGlobals.version able to");
  traceEvent(TRACE_INFO, "capture up to %d packets. If you are interested", MAX_NUM_PACKETS);
  traceEvent(TRACE_INFO, "in the full myGlobals.version please have a look at the ntop");
  traceEvent(TRACE_INFO, "home page http://www.ntop.org/.");
  traceEvent(TRACE_INFO, "-----------------------------------------------------------\n");
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

	if(dotp[i] == '.') strncpy(myGlobals.domainName, &dotp[i+1], sizeof(myGlobals.domainName));
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
			     userParm,     /* argument to thread function */
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

int _createMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {

  memset(mutexId, 0, sizeof(PthreadMutex));

  mutexId->mutex = CreateMutex(NULL, FALSE, NULL);
  mutexId->isInitialized = 1;

#ifdef DEBUG
  if (fileName)
    traceEvent(TRACE_INFO,
	       "INFO: createMutex() call with %x mutex [%s:%d]", mutexId,
	       fileName, fileLine);
#endif

  return(1);
}

/* ************************************ */

void _deleteMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {

#ifdef DEBUG
  if (fileName)
    traceEvent(TRACE_INFO,
	       "INFO: deleteMutex() call with %x(%c,%x) mutex [%s:%d]",
	       mutexId, (mutexId && mutexId->isInitialized) ? 'i' : '-',
	       mutexId ? mutexId->mutex : 0, fileName, fileLine);
#endif

  if(!mutexId->isInitialized) {
    traceEvent(TRACE_ERROR,
	       "ERROR: deleteMutex() call with a NULL mutex [%s:%d]",
	       fileName, fileLine);
    return;
  }

  ReleaseMutex(mutexId->mutex);
  CloseHandle(mutexId->mutex);

  memset(mutexId, 0, sizeof(PthreadMutex));
}

/* ************************************ */

int _accessMutex(PthreadMutex *mutexId, char* where,
		 char* fileName, int fileLine) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Locking 0x%X @ %s [%s:%d]",
	     mutexId->mutex, where, fileName, fileLine);
#endif

  WaitForSingleObject(mutexId->mutex, INFINITE);

  mutexId->numLocks++;
  mutexId->isLocked = 1;
  mutexId->lockTime = time(NULL);

  if(fileName != NULL) {
    strcpy(mutexId->lockFile, fileName);
    mutexId->lockLine = fileLine;
  }

  return(1);
}

/* ************************************ */

int _tryLockMutex(PthreadMutex *mutexId, char* where,
		  char* fileName, int fileLine) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Try to Lock 0x%X @ %s [%s:%d]",
	     mutexId->mutex, where, fileName, fileLine);
  fflush(stdout);
#endif

  if(WaitForSingleObject(mutexId->mutex, 0) == WAIT_FAILED)
    return(0);
  else {
    mutexId->numLocks++;
    mutexId->isLocked = 1;
    mutexId->lockTime = time(NULL);

    if(fileName != NULL) {
      strcpy(mutexId->lockFile, fileName);
      mutexId->lockLine = fileLine;
    }

    return(1);
  }
}

/* ************************************ */

int _releaseMutex(PthreadMutex *mutexId,
		  char* fileName, int fileLine) {

  time_t lockDuration;
  BOOL rc;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Unlocking 0x%X [%s:%d]",
	     mutexId->mutex, fileName, fileLine);
#endif
  rc = ReleaseMutex(mutexId->mutex);

  if((rc == 0) && (fileName)) {
    traceEvent(TRACE_ERROR, "ERROR while unlocking 0x%X [%s:%d] (LastError=%d)",
	       mutexId->mutex, fileName, fileLine, GetLastError());
  }

  lockDuration = time(NULL) - mutexId->lockTime;

  if((mutexId->maxLockedDuration < lockDuration)
     || (mutexId->maxLockedDurationUnlockLine == 0 /* Never set */)) {
    mutexId->maxLockedDuration = lockDuration;

    if(fileName != NULL) {
      strcpy(mutexId->maxLockedDurationUnlockFile, fileName);
      mutexId->maxLockedDurationUnlockLine = fileLine;
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "INFO: semaphore 0x%X [%s:%d] locked for %d secs",
	       &(mutexId->mutex), fileName, fileLine,
	       mutexId->maxLockedDuration);
#endif
  }

  mutexId->isLocked = 0;
  mutexId->numReleases++;
  if(fileName != NULL) {
    strcpy(mutexId->unlockFile, fileName);
    mutexId->unlockLine = fileLine;
  }

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
  traceEvent(TRACE_INFO, "Wait (%x)...", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Got signal (%d)...", rc);
#endif

  return(rc);
}

/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId) {
#ifdef DEBUG
  traceEvent(TRACE_INFO, "Signaling (%x)...", condvarId->condVar);
#endif
  return((int)PulseEvent(condvarId->condVar));
}

/* ************************************ */

void printAvailableInterfaces() {
  char ebuf[PCAP_ERRBUF_SIZE];
  int ifIdx=0, defaultIdx, i, numInterfaces = 0;
  char intNames[32][256];
  char *tmpDev = pcap_lookupdev(ebuf);
  
  if(tmpDev == NULL) {
    traceEvent(TRACE_INFO, "Unable to locate default interface (%s)", ebuf);
    exit(-1);
  }

  printf("\nAvailable interfaces (-i <interface index>):\n");

  if(!isWinNT()) {
    char *ifName = tmpDev;

    for(i=0;; i++) {
      if(tmpDev[i] == 0) {
	if(ifName[0] == '\0')
	  break;
	else {
	  printf("   [index=%d] '%s'\n", ifIdx, ifName);
	  numInterfaces++;

	  if(ifIdx < 32) {
	    strcpy(intNames[ifIdx], ifName);
	    if(defaultIdx == -1) {
	      if(strncmp(intNames[ifIdx], "PPP", 3) /* Avoid to use the PPP interface */
		 && strncmp(intNames[ifIdx], "ICSHARE", 6)) { /* Avoid to use the internet sharing interface */
		defaultIdx = ifIdx;
	      }
	    }
	  }

	  ifIdx++;
	  ifName = &tmpDev[i+1];
	}
      }
    }

    tmpDev = intNames[defaultIdx];
  } else {
    /* WinNT/2K */
    static char tmpString[128];
    int i, j,ifDescrPos = 0;
    unsigned short *ifName; /* UNICODE */
    char *ifDescr;

    ifName = tmpDev;

    while(*(ifName+ifDescrPos) || *(ifName+ifDescrPos-1))
      ifDescrPos++;
    ifDescrPos++;	/* Step over the extra '\0' */
    ifDescr = (char*)(ifName + ifDescrPos); /* cast *after* addition */

    while(tmpDev[0] != '\0') {

      for(j=0, i=0; !((tmpDev[i] == 0) && (tmpDev[i+1] == 0)); i++) {
	if(tmpDev[i] != 0)
	  tmpString[j++] = tmpDev[i];
      }

      tmpString[j++] = 0;
      printf("   [index=%d] %s\n             (%s)\n", ifIdx, ifDescr, tmpString);
      numInterfaces++;
      ifDescr += strlen(ifDescr)+1;
		 
      tmpDev = &tmpDev[i+3];
      strcpy(intNames[ifIdx++], tmpString);
      defaultIdx = 0;
    }
    if(defaultIdx != -1)
      tmpDev = intNames[defaultIdx]; /* Default */
  } /* while */

  if(numInterfaces == 0) {
    traceEvent(TRACE_WARNING, "WARNING: no interfaces available! This application cannot work");
    traceEvent(TRACE_WARNING, "         Make sure that winpcap is installed properly");
    traceEvent(TRACE_WARNING, "         and that you have network interfaces installed.");
  }
}

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

/* ************************************ */

void setnetent(int f)
{
  if(netf == NULL)
    netf = fopen(NETDB, "r" );
  else
    rewind(netf);
  _net_stayopen |= f;
}

/* ************************************ */

void endnetent() {
  if(netf) {
    fclose(netf);
    netf = NULL;
  }
  _net_stayopen = 0;
}

/* ************************************ */

static char *any(char *cp, char *match) {
  register char *mp, c;

  while (c = *cp) {
    for (mp = match; *mp; mp++)
      if(*mp == c)
	return (cp);
    cp++;
  }
  return ((char *)0);
}

/* ************************************ */

u_int32_t inet_network(const char *cp) {
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
   * The 4.4BSD myGlobals.version of this file also accepts 'x__' as a hexa
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

/* ************************************ */

struct netent* getnetent() {
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

/* ************************************ */

struct netent *getnetbyname(const char *name) {
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

/* ************************************ */

/* Find the first bit set in I.  */
int ffs (int i) {
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

int gettimeofday(struct timeval *tv,

#if defined(WIN32) && defined(__GNUC__)
		 /*
		   on mingw, struct timezone isn't defined so s/struct timezone/void/
		   Scott Renfro <scott@renfro.org>
		 */
		 void *notUsed
#else
		 struct timezone *notUsed
#endif
		 ) {
  tv->tv_sec = time(NULL);
  tv->tv_usec = 0;
  return(0);
}

/* ****************************************************** */

/* Courtesy of Wies-Software <wies@wiessoft.de> */
unsigned long waitForNextEvent(unsigned long ulDelay /* ms */) {
  unsigned long ulSlice = 1000L; /* 1 Second */

  while (myGlobals.capturePackets && (ulDelay > 0L)) {
    if (ulDelay < ulSlice)
      ulSlice = ulDelay;
    Sleep(ulSlice);
    ulDelay -= ulSlice;
  }

  return ulDelay;
}

/* ************************************************************* */

/* Code borrowed from http://www.cvsnt.org/ */

#define DEF_INPMODE  (ENABLE_LINE_INPUT|ENABLE_ECHO_INPUT|ENABLE_PROCESSED_INPUT)
#define HID_INPMODE  (ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT)

char* getpass(const char *prompt) {
  static char pwd_buf[128];
  size_t i;
  DWORD br;
  HANDLE hInput;
  DWORD dwMode;

  if(isWinNT()) {
    return("admin"); // Default password
  }

  hInput=GetStdHandle(STD_INPUT_HANDLE);
  fputs(prompt, stderr);
  fflush(stderr);
  fflush(stdout);
  FlushConsoleInputBuffer(hInput);
  GetConsoleMode(hInput,&dwMode);
  SetConsoleMode(hInput, ENABLE_PROCESSED_INPUT);

  for(i = 0; i < sizeof (pwd_buf) - 1; ++i) {
    ReadFile(GetStdHandle(STD_INPUT_HANDLE),pwd_buf+i,1,&br,NULL);
    if (pwd_buf[i] == '\r')
      break;
    fputc('*',stdout);
    fflush (stderr);
    fflush (stdout);
  }

  SetConsoleMode(hInput,dwMode);
  pwd_buf[i] = '\0';
  fputs ("\n", stderr);
  return pwd_buf;
}

/* *************************************************************

Windown NT/2K Service Registration Routines

Copyright© 2001 by Bill Giel/KC Multimedia and Design Group, Inc.

************************************************************* */


#ifdef __cplusplus
extern "C" {
#endif


  //
  //  FUNCTION: convertArgStringToArgList()
  //
  //  PURPOSE: Return an array of strings containing all arguments that
  //           are parsed from a tab-delimited argument string.
  //
  //  PARAMETERS:
  //    args  - The string array address to be allocated and receive the data
  //    len - pointer to an int that will contain the returned array length
  //    argstring - string containing arguments to be parsed.
  //
  //  RETURN VALUE:
  //    String array address containing the filtered arguments
  //    NULL on failure
  //
  LPTSTR* convertArgStringToArgList(LPTSTR *args, PDWORD pdwLen, LPTSTR lpszArgstring);

  //
  //  FUNCTION: convertArgListToArgString()
  //
  //  PURPOSE: Create a single tab-delimited string of arguments from
  //           an argument list
  //
  //  PARAMETERS:
  //    target - pointer to the string to be allocated and created
  //    start  - zero-based offest into the list to the first arg value used to
  //             build the list.
  //    argc - length of the argument list
  //    argv - array of strings, the argument list.
  //
  //  RETURN VALUE:
  //    Character pointer to the target string.
  //    NULL on failure
  //
  LPTSTR convertArgListToArgString(LPTSTR lpszTarget, DWORD dwStart, DWORD dwArgc, LPTSTR *lpszArgv);

#ifdef __cplusplus
}
#endif




#ifdef __cplusplus
extern "C" {
#endif

  //
  //  FUNCTION: getStringValue()
  //
  //  PURPOSE: Fetches a REG_SZ or REG_EXPAND_SZ string value
  //           from a specified registry key
  //
  //  PARAMETERS:
  //    lpVal - a string buffer for the desired value
  //    lpcbLen  - pointer to LONG value with buffer length
  //    hkRoot - the primary root key, e.g. HKEY_LOCAL_MACHINE
  //    lpszPath - the registry path to the subkey containing th desired value
  //    lpszValue - the name of the desired value
  //
  //  RETURN VALUE:
  //    0 on success, 1 on failure
  //
  int getStringValue(LPBYTE lpVal, LPDWORD lpcbLen, HKEY hkRoot, LPCTSTR lpszPath, LPTSTR lpszValue);

  //
  //  FUNCTION: setStringValue()
  //
  //  PURPOSE: Assigns a REG_SZ value to a
  //           specified registry key
  //
  //  PARAMETERS:
  //    lpVal - Constant byte array containing the value
  //    cbLen  - data length
  //    hkRoot - the primary root key, e.g. HKEY_LOCAL_MACHINE
  //    lpszPath - the registry path to the subkey containing th desired value
  //    lpszValue - the name of the desired value
  //
  //  RETURN VALUE:
  //    0 on success, 1 on failure
  //
  int setStringValue(CONST BYTE *lpVal, DWORD cbLen, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue);


  //
  //  FUNCTION: makeNewKey()
  //
  //  PURPOSE: Creates a new key at the specified path
  //
  //  PARAMETERS:
  //    hkRoot - the primary root key, e.g. HKEY_LOCAL_MACHINE
  //    lpszPath - the registry path to the new subkey
  //
  //  RETURN VALUE:
  //    0 on success, 1 on failure
  //
  int makeNewKey(HKEY hkRoot, LPCTSTR lpszPath);

  int setDwordValue(DWORD data, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue);

#ifdef __cplusplus
}
#endif



#ifdef __cplusplus
extern "C" {
#endif

  // =========================================================
  // TO DO: change as needed for specific Java app and service
  // =========================================================

  // internal name of the service
#define SZSERVICENAME        "ntop"

  // displayed name of the service
#define SZSERVICEDISPLAYNAME "ntop for Win32"

  // Service TYPE Permissable values:
  //		SERVICE_AUTO_START
  //		SERVICE_DEMAND_START
  //		SERVICE_DISABLED
#define SERVICESTARTTYPE SERVICE_AUTO_START


  // =========================================================
  // You should not need any changes below this line
  // =========================================================

  // Value name for app parameters
#define SZAPPPARAMS "AppParameters"

  // list of service dependencies - "dep1\0dep2\0\0"
  // If none, use ""
#define SZDEPENDENCIES ""

  //
  //  FUNCTION: getConsoleMode()
  //
  //  PURPOSE: Is the app running as a service or a console app.
  //
  //  RETURN VALUE:
  //    TRUE  - if running as a console application
  //    FALSE - if running as a service
  //
  BOOL getConsoleMode();

  //
  //  FUNCTION: ReportStatusToSCMgr()
  //
  //  PURPOSE: Sets the current status of the service and
  //           reports it to the Service Control Manager
  //
  //  PARAMETERS:
  //    dwCurrentState - the state of the service
  //    dwWin32ExitCode - error code to report
  //    dwWaitHint - worst case estimate to next checkpoint
  //
  //  RETURN VALUE:
  //    TRUE  - success
  //    FALSE - failure
  //
  BOOL ReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);


  //
  //  FUNCTION: AddToMessageLog(LPTSTR lpszMsg)
  //
  //  PURPOSE: Allows any thread to log an error message
  //
  //  PARAMETERS:
  //    lpszMsg - text for message
  //
  //  RETURN VALUE:
  //    none
  //
  void AddToMessageLog(LPTSTR lpszMsg);

  VOID ServiceStart(DWORD dwArgc, LPTSTR *lpszArgv);
  VOID ServiceStop();

#ifdef __cplusplus
}
#endif

//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: EVENT_GENERIC_INFORMATION
//
// MessageText:
//
//  %1
//
#define EVENT_GENERIC_INFORMATION        0x40000001L

//global variables
SERVICE_STATUS          ssStatus;
SERVICE_STATUS_HANDLE   sshStatusHandle;
DWORD                   dwErr = 0;
BOOL                    bConsole = FALSE;
TCHAR                   szErr[256];


#define SZFAILURE "StartServiceControlDispatcher failed!"
#define SZSCMGRFAILURE "OpenSCManager failed - %s\n"


int getStringValue(LPBYTE lpVal, LPDWORD lpcbLen, HKEY hkRoot, LPCTSTR lpszPath, LPTSTR lpszValue)
{

  LONG result;
  HKEY hKey;

  DWORD dwType;

  result = RegOpenKeyEx(
			hkRoot,
			lpszPath,
			(DWORD)0,
			KEY_EXECUTE | KEY_QUERY_VALUE,
			(PHKEY)&hKey);

  if(result != ERROR_SUCCESS){
    return 1;
  }

  result = RegQueryValueEx(
			   hKey,
			   lpszValue,
			   NULL,
			   (LPDWORD)&dwType,
			   lpVal,
			   lpcbLen);

  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS &&
	   (dwType == REG_SZ || dwType == REG_EXPAND_SZ));
}

int setStringValue(CONST BYTE *lpVal, DWORD cbLen, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue)
{

  LONG result;
  HKEY hKey;

  DWORD dwType = REG_SZ;

  result = RegOpenKeyEx(
			hkRoot,
			lpszPath,
			(DWORD)0,
			KEY_WRITE,
			(PHKEY)&hKey);

  if(result != ERROR_SUCCESS){
    return 1;
  }

  result = RegSetValueEx(
			 hKey,
			 lpszValue,
			 (DWORD)0,
			 dwType,
			 lpVal,
			 cbLen);

  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS);
}

int makeNewKey(HKEY hkRoot, LPCTSTR lpszPath)
{
  char *classname = "LocalSystem";

  LONG result;
  HKEY hKey;
  DWORD disposition;


  result = RegCreateKeyEx(
			  hkRoot,
			  lpszPath,
			  (DWORD)0,
			  classname,
			  REG_OPTION_NON_VOLATILE,
			  KEY_ALL_ACCESS,
			  NULL,
			  (PHKEY)&hKey,
			  (LPDWORD) &disposition);

  if(result != ERROR_SUCCESS){
    return 1;
  }


  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS);
}


int setDwordValue(DWORD data, HKEY hkRoot, LPCTSTR lpszPath, LPCTSTR lpszValue)
{

  LONG	result;
  HKEY	hKey;

  result = RegOpenKeyEx(hkRoot, lpszPath, (DWORD) 0, KEY_WRITE, (PHKEY) & hKey);

  if(result != ERROR_SUCCESS)
    {
      return 1;
    }

  result = RegSetValueEx(
			 hKey,
			 lpszValue,
			 0,
			 REG_DWORD,
			 (CONST BYTE*)&data,
			 sizeof(DWORD));

  RegCloseKey(hKey);

  return !(result == ERROR_SUCCESS);
}


BOOL getConsoleMode()
{
  return bConsole;
}

// Create an error message from GetLastError() using the
// FormatMessage API Call...
LPTSTR GetLastErrorText( LPTSTR lpszBuf, DWORD dwSize )
{
  DWORD dwRet;
  LPTSTR lpszTemp = NULL;



  dwRet = FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
			 FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_ARGUMENT_ARRAY,
			 NULL,
			 GetLastError(),
			 LANG_NEUTRAL,
			 (LPTSTR)&lpszTemp,
			 0,
			 NULL);

  // supplied buffer is not long enough
  if (!dwRet || ((long)dwSize < (long)dwRet+14)){
    lpszBuf[0] = TEXT('\0');
  }
  else{
    lpszTemp[lstrlen(lpszTemp)-2] = TEXT('\0');  //remove cr and newline character
    _stprintf( lpszBuf, TEXT("%s (0x%x)"), lpszTemp, GetLastError());
  }

  if (lpszTemp){
    GlobalFree((HGLOBAL) lpszTemp);
  }

  return lpszBuf;
}


// We'll try to install the service with this function, and save any
// runtime args for the service itself as a REG_SZ value in a registry
// subkey

void installService(int argc, char **argv)
{
  SC_HANDLE   schService;
  SC_HANDLE   schSCManager;

  TCHAR szPath[512];

  TCHAR szAppParameters[8192];

  char szParamKey[1025], szParamKey2[1025];

  sprintf(szParamKey,"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters",SZSERVICENAME);

  // Get the full path and filename of this program
  if ( GetModuleFileName( NULL, szPath, 512 ) == 0 ){
    _tprintf(TEXT("Unable to install %s - %s\n"), TEXT(SZSERVICEDISPLAYNAME),
	     GetLastErrorText(szErr, 256));
    return;
  }

  // Next, get a handle to the service control manager
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

  if ( schSCManager ) {

    schService = CreateService(schSCManager,   // SCManager database
			       TEXT(SZSERVICENAME),        // name of service
			       TEXT(SZSERVICEDISPLAYNAME), // name to display
			       SERVICE_ALL_ACCESS,         // desired access
			       SERVICE_WIN32_OWN_PROCESS,  // service type
			       SERVICESTARTTYPE,           // start type
			       SERVICE_ERROR_NORMAL,       // error control type
			       szPath,                     // service's binary
			       NULL,                       // no load ordering group
			       NULL,                       // no tag identifier
			       TEXT(SZDEPENDENCIES),       // dependencies
			       NULL,                       // LocalSystem account
			       NULL);                      // no password

    if (schService){
      _tprintf(TEXT("%s installed.\n"), TEXT(SZSERVICEDISPLAYNAME) );

      // Close the handle to this service object
      CloseServiceHandle(schService);

      //Make a registry key to support logging messages using the service name.
      sprintf(szParamKey2, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s",SZSERVICENAME);
      if(0 != makeNewKey(HKEY_LOCAL_MACHINE, szParamKey2)){
		_tprintf(TEXT("The EventLog subkey could not be created.\n"));
      }

      // Set the file value (where the message resources are located.... in this case, our runfile.)
      if(0 != setStringValue((const unsigned char *) szPath,
				    strlen(szPath) + 1,HKEY_LOCAL_MACHINE,
				    szParamKey2,TEXT("EventMessageFile")))
	{
	  _tprintf(TEXT("The Message File value could\nnot be assigned.\n"));
	}

      // Set the supported types flags.
      if(0 != setDwordValue(EVENTLOG_INFORMATION_TYPE,HKEY_LOCAL_MACHINE, szParamKey2,TEXT("TypesSupported"))){
	_tprintf(TEXT("The Types Supported value could\nnot be assigned.\n"));
      }

      // Try to create a subkey to hold the runtime args for the JavaVM and
      // Java application
      if(0 != makeNewKey(HKEY_LOCAL_MACHINE, szParamKey)){
	_tprintf(TEXT("Could not create Parameters subkey.\n"));
      } else {
	//Create an argument string from the argument list
	// J. R. Duarte: modified it to store the full command line
	convertArgListToArgString((LPTSTR) szAppParameters,0, argc, argv);
	if(NULL == szAppParameters){
	  _tprintf(TEXT("Could not create AppParameters string.\n"));
	}

	else{

	  // Try to save the argument string under the new subkey
	  if(0 != setStringValue(szAppParameters, strlen(szAppParameters)+1,
				 HKEY_LOCAL_MACHINE, szParamKey, SZAPPPARAMS)){
	    _tprintf(TEXT("Could not save AppParameters value.\n"));
	  }

	}
      }

    }
    else{
      _tprintf(TEXT("CreateService failed - %s\n"), GetLastErrorText(szErr, 256));
    }

    // Close the handle to the service control manager database
    CloseServiceHandle(schSCManager);
  }
  else{
    _tprintf(TEXT(SZSCMGRFAILURE), GetLastErrorText(szErr,256));
  }
}


// We'll try to stop, and then remove the service using this function.

void removeService()
{
  SC_HANDLE   schService;
  SC_HANDLE   schSCManager;
  char szParamKey2[1025];


  // First, get a handle to the service control manager
  schSCManager = OpenSCManager(NULL,
			       NULL,
			       SC_MANAGER_ALL_ACCESS);
  if (schSCManager){

    // Next get the handle to this service...
    schService = OpenService(schSCManager, TEXT(SZSERVICENAME), SERVICE_ALL_ACCESS);

    if (schService){

      // Now, try to stop the service by passing a STOP code thru the control manager
      if (ControlService( schService, SERVICE_CONTROL_STOP, &ssStatus)){

	_tprintf(TEXT("Stopping %s."), TEXT(SZSERVICEDISPLAYNAME));
	// Wait a second...
	Sleep( 1000 );

	// Poll the status of the service for SERVICE_STOP_PENDING
	while(QueryServiceStatus( schService, &ssStatus)){

	  // If the service has not stopped, wait another second
	  if ( ssStatus.dwCurrentState == SERVICE_STOP_PENDING ){
	    _tprintf(TEXT("."));
	    Sleep( 1000 );
	  }
	  else
	    break;
	}

	if ( ssStatus.dwCurrentState == SERVICE_STOPPED )
	  _tprintf(TEXT("\n%s stopped.\n"), TEXT(SZSERVICEDISPLAYNAME) );
	else
	  _tprintf(TEXT("\n%s failed to stop.\n"), TEXT(SZSERVICEDISPLAYNAME) );
      }

      // Now try to remove the service...
      if(DeleteService(schService)){
	_tprintf(TEXT("%s removed.\n"), TEXT(SZSERVICEDISPLAYNAME) );

	// Delete our eventlog registry key
	sprintf(szParamKey2, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s",SZSERVICENAME);
	RegDeleteKey(HKEY_LOCAL_MACHINE,szParamKey2);
      }else{
	_tprintf(TEXT("DeleteService failed - %s\n"), GetLastErrorText(szErr,256));
      }

      //Close this service object's handle to the service control manager
      CloseServiceHandle(schService);
    }
    else{
      _tprintf(TEXT("OpenService failed - %s\n"), GetLastErrorText(szErr,256));
    }

    // Finally, close the handle to the service control manager's database
    CloseServiceHandle(schSCManager);


  }
  else{
    _tprintf(TEXT(SZSCMGRFAILURE), GetLastErrorText(szErr,256));
  }
}

/* ********************************************* */

extern int ntop_main(int argc, char *argv[]);
extern void usage (FILE * fd);

DWORD _dwArgc;
LPTSTR *_lpszArgv;
HANDLE  hServerStopEvent = NULL;


void* invokeNtop(LPTSTR szAppParameters) {
  DWORD dwNewArgc, i;
  LPTSTR *lpszNewArgv;
  LPTSTR *lpszTmpArgv;

  // SetConsoleCtrlHandler(logoffHandler, TRUE);

  // J. R. Duarte: convert the string argument back to argc & argv
  lpszNewArgv = convertArgStringToArgList(lpszNewArgv, &dwNewArgc, szAppParameters);

  // J. R. Duarte: to handle removing the Windows-specific command
  // line option when running from the command line or as a service
  if (!stricmp(lpszNewArgv[1],"/c") || !stricmp(lpszNewArgv[1],"/i"))
    {
      lpszTmpArgv = lpszNewArgv;		// make a copy of argv

      for(i=0; i < dwNewArgc ;i++)	{
	if (i == 0)
	  lpszNewArgv[0] = lpszTmpArgv[0];
	else if (i > 1)
	  lpszNewArgv[i - 1] = lpszTmpArgv[i];
      }

      dwNewArgc--;
    }

  ntop_main(dwNewArgc, lpszNewArgv);
  return(NULL);
}

// This method is called from ServiceMain() when NT starts the service
// or by runService() if run from the console.

VOID ServiceStart (DWORD dwArgc, LPTSTR *lpszArgv)
{
  pthread_t ntopThread;
  TCHAR szAppParameters[8192];

  // Let the service control manager know that the service is
  // initializing.
  if (!ReportStatus(SERVICE_START_PENDING,
		    NO_ERROR,
		    3000))
    //goto cleanup;
    return;


  // Create a Stop Event
  hServerStopEvent = CreateEvent(
				 NULL,
				 TRUE,
				 FALSE,
				 NULL);


  if ( hServerStopEvent == NULL)
    goto cleanup;

  if(dwArgc > 0)
    _dwArgc = dwArgc, _lpszArgv = lpszArgv;
  else {
    char *progName = SZSERVICENAME;
    _dwArgc = 1, _lpszArgv = &progName;
  }

  if (!ReportStatus(SERVICE_RUNNING,NO_ERROR,0)){
    goto cleanup;
  }

  // createThread(&ntopThread, invokeNtop, NULL);
  // J. R. Duarte: Create an argument string from the argument list
  convertArgListToArgString((LPTSTR) szAppParameters,0, dwArgc, lpszArgv);
  if(NULL == szAppParameters){
    _tprintf(TEXT("Could not create AppParameters string.\n"));
  }
  createThread(&ntopThread, invokeNtop, szAppParameters);

  // Wait for the stop event to be signalled.
  WaitForSingleObject(hServerStopEvent,INFINITE);

 cleanup:

  if (hServerStopEvent)
    CloseHandle(hServerStopEvent);
}

/* ********************************************* */

VOID ServiceStop() {
  SetEvent(hServerStopEvent);
}

/* ************************************ */

// This function permits running the application from the
// console.

void runService(int argc, char ** argv)
{
  DWORD dwArgc;
  LPTSTR *lpszArgv;

#ifdef UNICODE
  lpszArgv = CommandLineToArgvW(GetCommandLineW(), &(dwArgc) );
#else
  dwArgc   = (DWORD) argc;
  lpszArgv = argv;
#endif

  _tprintf(TEXT("Running %s.\n"), TEXT(SZSERVICEDISPLAYNAME));

  ServiceStart( dwArgc, lpszArgv);
}

/* ************************************ */

// If running as a service, use event logging to post a message
// If not, display the message on the console.

VOID AddToMessageLog(LPTSTR lpszMsg)
{
  HANDLE  hEventSource;
  TCHAR	szMsg[4096];

#ifdef UNICODE
  LPCWSTR  lpszStrings[1];
#else
  LPCSTR   lpszStrings[1];
#endif

  if(!isWinNT()) {
    char *msg = (char*)lpszMsg;
    printf("%s", msg);
    if(msg[strlen(msg)-1] != '\n')
      printf("\n");
    return;
  }

  if (!bConsole)
    {
      hEventSource = RegisterEventSource(NULL, TEXT(SZSERVICENAME));

      _stprintf(szMsg, TEXT("%s: %s"), SZSERVICENAME, lpszMsg);

      lpszStrings[0] = szMsg;

      if (hEventSource != NULL) {
		ReportEvent(hEventSource,
				EVENTLOG_INFORMATION_TYPE,
				0,
				EVENT_GENERIC_INFORMATION,
				NULL,
				1,
				0,
				lpszStrings,
				NULL);

		DeregisterEventSource(hEventSource);
      }
    } else {
    _tprintf(TEXT("%s\n"), lpszMsg);
  }
}

/* ************************************ */

// Throughout the program, calls to SetServiceStatus are required
// which are handled by calling this function. Here, the non-constant
// members of the SERVICE_STATUS struct are assigned and SetServiceStatus
// is called with the struct. Note that we will not report to the service
// control manager if we are running as  console application.

BOOL ReportStatus(DWORD dwCurrentState,
		  DWORD dwWin32ExitCode,
		  DWORD dwWaitHint)
{
  static DWORD dwCheckPoint = 1;
  BOOL bResult = TRUE;


  if ( !bConsole )
    {
      if (dwCurrentState == SERVICE_START_PENDING)
	ssStatus.dwControlsAccepted = 0;
      else
	ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

      ssStatus.dwCurrentState = dwCurrentState;
      ssStatus.dwWin32ExitCode = dwWin32ExitCode;
      ssStatus.dwWaitHint = dwWaitHint;

      if ( ( dwCurrentState == SERVICE_RUNNING ) ||
	   ( dwCurrentState == SERVICE_STOPPED ) )
	ssStatus.dwCheckPoint = 0;
      else
	ssStatus.dwCheckPoint = dwCheckPoint++;

      if (!(bResult = SetServiceStatus( sshStatusHandle, &ssStatus))) {
	AddToMessageLog(TEXT("SetServiceStatus"));
      }
    }

  return bResult;
}

/* ************************************ */

// Each Win32 service must have a control handler to respond to
// control requests from the dispatcher.

VOID WINAPI controlHandler(DWORD dwCtrlCode)
{

  switch(dwCtrlCode)
    {

    case SERVICE_CONTROL_STOP:
      // Request to stop the service. Report SERVICE_STOP_PENDING
      // to the service control manager before calling ServiceStop()
      // to avoid a "Service did not respond" error.
      ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
      ServiceStop();
      return;


    case SERVICE_CONTROL_INTERROGATE:
      // This case MUST be processed, even though we are not
      // obligated to do anything substantial in the process.
      break;

    default:
      // Any other cases...
      break;

    }

  // After invocation of this function, we MUST call the SetServiceStatus
  // function, which is accomplished through our ReportStatus function. We
  // must do this even if the current status has not changed.
  ReportStatus(ssStatus.dwCurrentState, NO_ERROR, 0);
}

/* ************************************ */

// The ServiceMain function is the entry point for the service.
void WINAPI serviceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
  TCHAR szAppParameters[8192];
  LONG lLen = 8192;

  LPTSTR *lpszNewArgv = NULL;
  DWORD dwNewArgc;

  UINT i;

  char szParamKey[1025];

  sprintf(szParamKey,"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters",SZSERVICENAME);

  // Call RegisterServiceCtrlHandler immediately to register a service control
  // handler function. The returned SERVICE_STATUS_HANDLE is saved with global
  // scope, and used as a service id in calls to SetServiceStatus.
  sshStatusHandle = RegisterServiceCtrlHandler( TEXT(SZSERVICENAME), controlHandler);

  if (!sshStatusHandle)
    goto finally;

  // The global ssStatus SERVICE_STATUS structure contains information about the
  // service, and is used throughout the program in calls made to SetStatus through
  // the ReportStatus function.
  ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  ssStatus.dwServiceSpecificExitCode = 0;


  // If we could guarantee that all initialization would occur in less than one
  // second, we would not have to report our status to the service control manager.
  // For good measure, we will assign SERVICE_START_PENDING to the current service
  // state and inform the service control manager through our ReportStatus function.
  if (!ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000))
    goto finally;

  // When we installed this service, we probably saved a list of runtime args
  // in the registry as a subkey of the key for this service. We'll try to get
  // it here...
  if(0 != getStringValue(szAppParameters,(LPDWORD)&lLen, HKEY_LOCAL_MACHINE, szParamKey, SZAPPPARAMS)){
    dwNewArgc = 0;
    lpszNewArgv = NULL;
  } else {
    //If we have an argument string, convert it to a list of argc/argv type...
    lpszNewArgv = convertArgStringToArgList(lpszNewArgv, &dwNewArgc, szAppParameters);
  }

  // Do it! In ServiceStart, we'll send additional status reports to the
  // service control manager, especially the SERVICE_RUNNING report once
  // our JVM is initiallized and ready to be invoked.
  ServiceStart(dwNewArgc, lpszNewArgv);

  // Release the allocated storage used by our arg list. Java programmers
  // might remember this kind of stuff.
  for(i=0; i<dwNewArgc; i++){
    GlobalFree((HGLOBAL)lpszNewArgv[i]);
  }
  if(dwNewArgc > 0)
    GlobalFree((HGLOBAL)lpszNewArgv);

 finally:

  // Report the stopped status to the service control manager, if we have
  // a valid server status handle.
  if (sshStatusHandle)
    (VOID)ReportStatus( SERVICE_STOPPED, dwErr, 0);
}

/* ************************************ */

void main(int argc, char **argv)
{
  // The StartServiceCtrlDispatcher requires this table to specify
  // the ServiceMain function to run in the calling process. The first
  // member in this example is actually ignored, since we will install
  // our service as a SERVICE_WIN32_OWN_PROCESS service type. The NULL
  // members of the last entry are necessary to indicate the end of
  // the table;
  SERVICE_TABLE_ENTRY serviceTable[] =
    {
      { TEXT(SZSERVICENAME), (LPSERVICE_MAIN_FUNCTION)serviceMain },
      { NULL, NULL }
    };

  TCHAR szAppParameters[8192];

  if(!isWinNT()) {
    convertArgListToArgString((LPTSTR) szAppParameters,0, argc, argv);
    if(NULL == szAppParameters){
      _tprintf(TEXT("Could not create AppParameters string.\n"));
    }
    invokeNtop(szAppParameters);
    return;
  }

  // This app may be started with one of three arguments, /i, /r, and
  // /c, or /?, followed by actual program arguments. These arguments
  // indicate if the program is to be installed, removed, run as a
  // console application, or to display a usage message.
  if(argc > 1){
    if(!stricmp(argv[1],"/i")){
      installService(argc,argv);
      printf("NOTE: the default password for the 'admin' user has been set to 'admin'.");
    }
    else if(!stricmp(argv[1],"/r")){
      removeService();
    }
    else if(!stricmp(argv[1],"/c")){
      bConsole = TRUE;
      runService(argc,argv);
    }
    else{
      printf("\nUnrecognized option: %s\n", argv[1]);
      printf("Available options:\n");
      printf("/i [ntop options] - Install ntop as service\n");
      printf("/c                - Run ntop on a console\n");
      printf("/r                - Deinstall the service\n\n");
      initNtopGlobals(argc, argv); initWinsock32(); // Necessary for usage()
      usage(stdout);
    }
    exit(0);

  }

  // If main is called without any arguments, it will probably be by the
  // service control manager, in which case StartServiceCtrlDispatcher
  // must be called here. A message will be printed just in case this
  // happens from the console.
  printf("\nNOTE:\nUnder your version of Windows, ntop is started as a service.\n");
  printf("Please open the services control panel to start/stop ntop,\n");
  printf("or type ntop /h to see all the available options.\n");

  if(!StartServiceCtrlDispatcher(serviceTable)) {
    printf("\n%s\n", SZFAILURE);
    AddToMessageLog(TEXT(SZFAILURE));
  }
}

/* ************************************ */

LPTSTR *convertArgStringToArgList(LPTSTR *lpszArgs, PDWORD pdwLen,
				  LPTSTR lpszArgstring)
{
  UINT uCount;
  LPTSTR lpszArg, lpszToken;


  if(strlen(lpszArgstring) == 0){
    *pdwLen = 0;
    //lpszArgs = NULL;
    return NULL;
  }

  if(NULL == (lpszArg = (LPTSTR)GlobalAlloc(GMEM_FIXED,strlen(lpszArgstring)+1))){
    *pdwLen = 0;
    //lpszArgs = NULL;
    return NULL;
  }

  strcpy(lpszArg, lpszArgstring);

  lpszToken = strtok( lpszArg, "\t" );
  uCount = 0;
  while( lpszToken != NULL ){
    uCount++;
    lpszToken = strtok( NULL, "\t");
  }

  GlobalFree((HGLOBAL)lpszArg);

  lpszArgs = (LPTSTR *)GlobalAlloc(GMEM_FIXED,uCount * sizeof(LPTSTR));
  *pdwLen = uCount;


  lpszToken = strtok(lpszArgstring,"\t");
  uCount = 0;
  while(lpszToken != NULL){
    lpszArgs[uCount] = (LPTSTR)GlobalAlloc(GMEM_FIXED,strlen(lpszToken)+1);
    strcpy(lpszArgs[uCount],lpszToken);
    uCount++;
    lpszToken = strtok( NULL, "\t");
  }


  return lpszArgs;

}

/* ************************************ */

LPTSTR convertArgListToArgString(LPTSTR lpszTarget,
				 DWORD dwStart, DWORD dwArgc,
				 LPTSTR *lpszArgv)
{
  UINT i;

  if(dwStart >= dwArgc){
    return NULL;
  }

  *lpszTarget = 0;

  for(i=dwStart; i<dwArgc; i++){

    if(i != dwStart){
      strcat(lpszTarget,"\t");
    }
    strcat(lpszTarget,lpszArgv[i]);
  }

  return lpszTarget;
}

/* ********************************* */

int spawnProcess(char* theProcess)
{
  STARTUPINFO startupInfo;
  PROCESS_INFORMATION procInfo;
  BOOL success;

  GetStartupInfo(&startupInfo);
  success = CreateProcess(NULL,
			  theProcess,
			  NULL, NULL, FALSE,
			  CREATE_NEW_CONSOLE,
			  NULL, NULL, &startupInfo, &procInfo);

  if(!success)
    return(-1);
  else
    return(0);
}
