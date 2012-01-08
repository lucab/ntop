/*
 *  Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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
u_char isNtopAservice;


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
    traceEvent(CONST_TRACE_FATALERROR, "Unable to initialise Winsock 2.x.");
    exit(-1);
  }

  ntop_author  = "Luca Deri <deri@ntop.org>";

  if(!isWinNT()) {
    osName = "Win95/98/ME";
    strcpy(_wdir, ".");
  } else {
    osName = "WinNT/2K/XP/Vista/Win7";

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

    /* traceEvent(CONST_TRACE_ERROR, "Wdir=%s", _wdir); */
  }

    
#ifdef WIN32
  if(myGlobals.runningPref.pcapLogBasePath) free(myGlobals.runningPref.pcapLogBasePath); myGlobals.runningPref.pcapLogBasePath = strdup(_wdir);
  if(myGlobals.dbPath)          free(myGlobals.dbPath); myGlobals.dbPath = strdup(_wdir);
  if(myGlobals.spoolPath)       free(myGlobals.spoolPath); myGlobals.spoolPath = strdup(_wdir);
#endif


#ifdef WIN32_DEMO
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "-----------------------------------------------------------");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "WARNING: this application is a limited ntop version able to");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "capture up to %d packets. If you are interested", MAX_NUM_PACKETS);
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "in the full version please have a look at the ntop");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "home page http://www.ntop.org/.");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "-----------------------------------------------------------");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "");
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
  nRet = gethostname(szLclHost, sizeof(szLclHost));
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

	if(dotp[i] == '.') strncpy(myGlobals.runningPref.domainName, &dotp[i+1], sizeof(myGlobals.runningPref.domainName));
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

   http://www-128.ibm.com/developerworks/eserver/articles/es-MigratingWin32toLinux.html

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

int _killThread(pthread_t *threadId) {
  CloseHandle((HANDLE)*threadId);
  return(0);
}

/* ************************************ */

int _joinThread(pthread_t *threadId) {
  WaitForSingleObject((HANDLE)*threadId, INFINITE);
  return(0);
}

/* ************************************ */

int _createMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {

  memset(mutexId, 0, sizeof(PthreadMutex));

  mutexId->mutex = CreateMutex(NULL, FALSE, NULL);
  mutexId->isInitialized = 1;

#ifdef DEBUG
  if (fileName)
    traceEvent(CONST_TRACE_INFO,
	       "DEBUG: createMutex() call with %x mutex [%s:%d]", mutexId,
	       fileName, fileLine);
#endif

  return(1);
}

/* ************************************ */

void _deleteMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {

#ifdef DEBUG
  if (fileName)
    traceEvent(CONST_TRACE_INFO,
	       "DEBUG: deleteMutex() call with %x(%c,%x) mutex [%s:%d]",
	       mutexId, (mutexId && mutexId->isInitialized) ? 'i' : '-',
	       mutexId ? mutexId->mutex : 0, fileName, fileLine);
#endif

  if(!mutexId->isInitialized) {
    traceEvent(CONST_TRACE_WARNING,
	       "deleteMutex() call with a NULL mutex [%s:%d]",
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
  traceEvent(CONST_TRACE_INFO, "Locking 0x%X @ %s [%s:%d]",
	     mutexId->mutex, where, fileName, fileLine);
#endif

  WaitForSingleObject(mutexId->mutex, INFINITE);

#ifdef MUTEX_DEBUG

  mutexId->numLocks++;
  mutexId->isLocked = 1;
  if(!myGlobals.runningPref.disableMutexExtraInfo) {
    memcpy(&(mutexId->lock), &(mutexId->attempt), sizeof(Holder));
    memset(&(mutexId->attempt), 0, sizeof(Holder));
  }
#endif

  return(0);
}

/* ************************************ */

int _tryLockMutex(PthreadMutex *mutexId, char* where,
		  char* fileName, int fileLine) {
  int rc;
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Try to Lock 0x%X @ %s [%s:%d]",
	     mutexId->mutex, where, fileName, fileLine);
  fflush(stdout);
#endif

  rc = WaitForSingleObject(mutexId->mutex, 0);

  /* traceEvent(CONST_TRACE_INFO, "_tryLockMutex=%d", rc); */

  if(rc != WAIT_OBJECT_0 /* OK */)
    return(1);
  else {
#ifdef MUTEX_DEBUG

    mutexId->numLocks++;
    mutexId->isLocked = 1;
    if(!myGlobals.runningPref.disableMutexExtraInfo) {
      memcpy(&(mutexId->lock), &(mutexId->attempt), sizeof(Holder));
      memset(&(mutexId->attempt), 0, sizeof(Holder));
    }
#endif

    return(0);
  }
}

/* ************************************ */

int _releaseMutex(PthreadMutex *mutexId, char* fileName, int fileLine) {

  time_t lockDuration;
  BOOL rc;

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Unlocking 0x%X [%s:%d]",
	     mutexId->mutex, fileName, fileLine);
#endif
  rc = ReleaseMutex(mutexId->mutex);

#ifdef MUTEX_DEBUG
  if((rc == 0) && (fileName)) {
    traceEvent(CONST_TRACE_WARNING, "Unlock failed for 0x%X [%s:%d] (LastError=%d)",
	       mutexId->mutex, fileName, fileLine, GetLastError());
  }
  mutexId->isLocked = 0;
  mutexId->numReleases++;

  if(!myGlobals.runningPref.disableMutexExtraInfo) {
    setHolder(mutexId->unlock);
    lockDuration = timeval_subtract(mutexId->unlock.time, mutexId->lock.time);

    if((mutexId->maxLockedDuration < lockDuration)
       || (mutexId->max.line == 0 /* Never set */)) {
      memcpy(&(mutexId->max), &(mutexId->lock), sizeof(Holder));
      mutexId->maxLockedDuration = lockDuration;
    }
  }
#endif

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "DEBUG: semaphore 0x%X [%s:%d] locked for %d secs",
	     &(mutexId->mutex), fileName, fileLine,
	     mutexId->maxLockedDuration);
#endif

  return(0);
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
  traceEvent(CONST_TRACE_INFO, "Wait (%x)...", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Got signal (%d)...", rc);
#endif

  return(rc);
}

/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId, u_int8_t broadcast) {
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Signaling (%x)...", condvarId->condVar);
#endif
  /* FIX: handle "u_int8_t broadcast" */
  return((int)PulseEvent(condvarId->condVar));
}

/* ************************************ */

void printAvailableInterfaces() {
  char ebuf[CONST_SIZE_PCAP_ERR_BUF];
  int i, numInterfaces = 0;
  pcap_if_t *devpointer;

  ebuf[0] = '\0';

  printf("\nAvailable interfaces (-i <interface index>):\n");

  if(pcap_findalldevs(&devpointer, ebuf) < 0) {
    ;
  } else {
    for (i = 0; devpointer != 0; i++) {
      if(validInterface(devpointer->description)) {
	printf("   [index=%d] %s\n             (%s)\n",
	       numInterfaces++, devpointer->description, devpointer->name);
      }

      devpointer = devpointer->next;
    } /* for */
  } /* else */


  if(numInterfaces == 0) {
    traceEvent(CONST_TRACE_WARNING, "No interfaces available! This application cannot work");
    traceEvent(CONST_TRACE_WARNING, "         Make sure that winpcap is installed properly");
    traceEvent(CONST_TRACE_WARNING, "         and that you have network interfaces installed.");
  }
}

/* ************************************ */

#define CONST_WIN32_PATH_NETWORKS	"networks"

#define	MAX_WIN32_NET_ALIASES 35

static FILE *netf = NULL;
static char line[BUFSIZ+1];
static struct netent net;
static char *net_aliases[MAX_WIN32_NET_ALIASES];
static char *any(char *, char *);

int _net_stayopen;

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

#if 0

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
    if(q < &net_aliases[MAX_WIN32_NET_ALIASES - 1])
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
#endif

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

  while ((myGlobals.ntopRunState < FLAG_NTOPSTATE_SHUTDOWN) && (ulDelay > 0L)) {
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

   Copyright 2001 by Bill Giel/KC Multimedia and Design Group, Inc.

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

  TCHAR szPath[512], szDescr[256];

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

      /* ****************************************** */
      // Set the service name. Courtesy of Yuri Francalacci <yuri@ntop.org>
      sprintf(szParamKey2, "SYSTEM\\CurrentControlSet\\Services\\%s",SZSERVICENAME);
      safe_snprintf(__FILE__, __LINE__, szDescr, sizeof(szDescr), "Ntop v.%s %s - Web-based network traffic monitor. http://www.ntop.org/",
		    version, "MT");

      // Set the file value (where the message resources are located.... in this case, our runfile.)
      if(0 != setStringValue((const unsigned char *)szDescr,
			     strlen(szDescr) + 1,HKEY_LOCAL_MACHINE, szParamKey2,TEXT("Description")))
	{
	  _tprintf(TEXT("The Message File value could\nnot be assigned.\n"));
	}
      /* ********************************************** */


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
  LPTSTR *lpszNewArgv=NULL;
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
  SetEvent(hServerStopEvent); // Signal main thread that we're leaving
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

  u_int i;

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

void ifprint(pcap_if_t *d)
{
  /* Name */
  printf("%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);
}

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

  isNtopAservice = 0;

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
      runService(argc, argv);
    }
    else {
      printf("\nUnrecognized option: %s\n", argv[1]);
      printf("Available options:\n");
      printf("/i [ntop options] - Install ntop as service\n");
      printf("/c                - Run ntop on a console\n");
      printf("/r                - Deinstall the service\n");
      printf("/h                - Prints this help\n\n");
      initNtopGlobals(argc, argv, argc, argv); 
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

  isNtopAservice = 1;
  if(!StartServiceCtrlDispatcher(serviceTable)) {
    printf("\n%s\n", SZFAILURE);
    AddToMessageLog(TEXT(SZFAILURE));
  }
}

/* ************************************ */

LPTSTR *convertArgStringToArgList(LPTSTR *lpszArgs, PDWORD pdwLen,
				  LPTSTR lpszArgstring)
{
  u_int uCount;
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
  u_int i;

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

/* ******************************* */

static int get_drive_serial(char *drive, unsigned long *driveSerial) {
  return(GetVolumeInformation(drive, NULL, 0, driveSerial, NULL, NULL, NULL, 0 ));
}

/* Use the HDD serial number to identify a PC. This is necesary as ntop can
   run from a mobile device hence it is necessary not to mix prefs and data
   coming from different PCs
*/
void get_serial(unsigned long *driveSerial) {
  *driveSerial = 0;

  if(!get_drive_serial("C:\\", driveSerial))
    get_drive_serial("D:\\", driveSerial);
}


/* ********************************* */

static char * _strptime(const char *, const char *, struct tm *);

static int got_GMT;

#define asizeof(a)	(sizeof (a) / sizeof ((a)[0]))

struct lc_time_T {
  const char *    mon[12];
  const char *    month[12];
  const char *    wday[7];
  const char *    weekday[7];
  const char *    X_fmt;     
  const char *    x_fmt;
  const char *    c_fmt;
  const char *    am;
  const char *    pm;
  const char *    date_fmt;
  const char *    alt_month[12];
  const char *    Ef_fmt;
  const char *    EF_fmt;
};

struct lc_time_T _time_localebuf;
int _time_using_locale;

const struct lc_time_T	_C_time_locale = {
  {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  }, {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
  }, {
    "Sun", "Mon", "Tue", "Wed",
    "Thu", "Fri", "Sat"
  }, {
    "Sunday", "Monday", "Tuesday", "Wednesday",
    "Thursday", "Friday", "Saturday"
  },

  /* X_fmt */
  "%H:%M:%S",

  /*
  ** x_fmt
  ** Since the C language standard calls for
  ** "date, using locale's date format," anything goes.
  ** Using just numbers (as here) makes Quakers happier;
  ** it's also compatible with SVR4.
  */
  "%m/%d/%y",

  /*
  ** c_fmt (ctime-compatible)
  ** Not used, just compatibility placeholder.
  */
  NULL,

  /* am */
  "AM",

  /* pm */
  "PM",

  /* date_fmt */
  "%a %Ef %X %Z %Y",
	
  {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
  },

  /* Ef_fmt
  ** To determine short months / day order
  */
  "%b %e",

  /* EF_fmt
  ** To determine long months / day order
  */
  "%B %e"
};

#define Locale (&_C_time_locale)

static char *
_strptime(const char *buf, const char *fmt, struct tm *tm)
{
  char c;
  const char *ptr;
  int i,
    len;
  int Ealternative, Oalternative;

  ptr = fmt;
  while (*ptr != 0) {
    if (*buf == 0)
      break;

    c = *ptr++;

    if (c != '%') {
      if (isspace((unsigned char)c))
	while (*buf != 0 && isspace((unsigned char)*buf))
	  buf++;
      else if (c != *buf++)
	return 0;
      continue;
    }

    Ealternative = 0;
    Oalternative = 0;
  label:
    c = *ptr++;
    switch (c) {
    case 0:
    case '%':
      if (*buf++ != '%')
	return 0;
      break;

    case '+':
      buf = _strptime(buf, Locale->date_fmt, tm);
      if (buf == 0)
	return 0;
      break;

    case 'C':
      if (!isdigit((unsigned char)*buf))
	return 0;

      /* XXX This will break for 3-digit centuries. */
      len = 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (i < 19)
	return 0;

      tm->tm_year = i * 100 - 1900;
      break;

    case 'c':
      /* NOTE: c_fmt is intentionally ignored */
      buf = _strptime(buf, "%a %Ef %T %Y", tm);
      if (buf == 0)
	return 0;
      break;

    case 'D':
      buf = _strptime(buf, "%m/%d/%y", tm);
      if (buf == 0)
	return 0;
      break;

    case 'E':
      if (Ealternative || Oalternative)
	break;
      Ealternative++;
      goto label;

    case 'O':
      if (Ealternative || Oalternative)
	break;
      Oalternative++;
      goto label;

    case 'F':
    case 'f':
      if (!Ealternative)
	break;
      buf = _strptime(buf, (c == 'f') ? Locale->Ef_fmt : Locale->EF_fmt, tm);
      if (buf == 0)
	return 0;
      break;

    case 'R':
      buf = _strptime(buf, "%H:%M", tm);
      if (buf == 0)
	return 0;
      break;

    case 'r':
      buf = _strptime(buf, "%I:%M:%S %p", tm);
      if (buf == 0)
	return 0;
      break;

    case 'T':
      buf = _strptime(buf, "%H:%M:%S", tm);
      if (buf == 0)
	return 0;
      break;

    case 'X':
      buf = _strptime(buf, Locale->X_fmt, tm);
      if (buf == 0)
	return 0;
      break;

    case 'x':
      buf = _strptime(buf, Locale->x_fmt, tm);
      if (buf == 0)
	return 0;
      break;

    case 'j':
      if (!isdigit((unsigned char)*buf))
	return 0;

      len = 3;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (i < 1 || i > 366)
	return 0;

      tm->tm_yday = i - 1;
      break;

    case 'M':
    case 'S':
      if (*buf == 0 || isspace((unsigned char)*buf))
	break;

      if (!isdigit((unsigned char)*buf))
	return 0;

      len = 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }

      if (c == 'M') {
	if (i > 59)
	  return 0;
	tm->tm_min = i;
      } else {
	if (i > 60)
	  return 0;
	tm->tm_sec = i;
      }

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'H':
    case 'I':
    case 'k':
    case 'l':
      /*
       * Of these, %l is the only specifier explicitly
       * documented as not being zero-padded.  However,
       * there is no harm in allowing zero-padding.
       *
       * XXX The %l specifier may gobble one too many
       * digits if used incorrectly.
       */
      if (!isdigit((unsigned char)*buf))
	return 0;

      len = 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (c == 'H' || c == 'k') {
	if (i > 23)
	  return 0;
      } else if (i > 12)
	return 0;

      tm->tm_hour = i;

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'p':
      /*
       * XXX This is bogus if parsed before hour-related
       * specifiers.
       */
      len = strlen(Locale->am);
      if (strncasecmp(buf, Locale->am, len) == 0) {
	if (tm->tm_hour > 12)
	  return 0;
	if (tm->tm_hour == 12)
	  tm->tm_hour = 0;
	buf += len;
	break;
      }

      len = strlen(Locale->pm);
      if (strncasecmp(buf, Locale->pm, len) == 0) {
	if (tm->tm_hour > 12)
	  return 0;
	if (tm->tm_hour != 12)
	  tm->tm_hour += 12;
	buf += len;
	break;
      }

      return 0;

    case 'A':
    case 'a':
      for (i = 0; i < asizeof(Locale->weekday); i++) {
	if (c == 'A') {
	  len = strlen(Locale->weekday[i]);
	  if (strncasecmp(buf,
			  Locale->weekday[i],
			  len) == 0)
	    break;
	} else {
	  len = strlen(Locale->wday[i]);
	  if (strncasecmp(buf,
			  Locale->wday[i],
			  len) == 0)
	    break;
	}
      }
      if (i == asizeof(Locale->weekday))
	return 0;

      tm->tm_wday = i;
      buf += len;
      break;

    case 'U':
    case 'W':
      /*
       * XXX This is bogus, as we can not assume any valid
       * information present in the tm structure at this
       * point to calculate a real value, so just check the
       * range for now.
       */
      if (!isdigit((unsigned char)*buf))
	return 0;

      len = 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (i > 53)
	return 0;

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'w':
      if (!isdigit((unsigned char)*buf))
	return 0;

      i = *buf - '0';
      if (i > 6)
	return 0;

      tm->tm_wday = i;

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'd':
    case 'e':
      /*
       * The %e specifier is explicitly documented as not
       * being zero-padded but there is no harm in allowing
       * such padding.
       *
       * XXX The %e specifier may gobble one too many
       * digits if used incorrectly.
       */
      if (!isdigit((unsigned char)*buf))
	return 0;

      len = 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (i > 31)
	return 0;

      tm->tm_mday = i;

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'B':
    case 'b':
    case 'h':
      for (i = 0; i < asizeof(Locale->month); i++) {
	if (Oalternative) {
	  if (c == 'B') {
	    len = strlen(Locale->alt_month[i]);
	    if (strncasecmp(buf,
			    Locale->alt_month[i],
			    len) == 0)
	      break;
	  }
	} else {
	  if (c == 'B') {
	    len = strlen(Locale->month[i]);
	    if (strncasecmp(buf,
			    Locale->month[i],
			    len) == 0)
	      break;
	  } else {
	    len = strlen(Locale->mon[i]);
	    if (strncasecmp(buf,
			    Locale->mon[i],
			    len) == 0)
	      break;
	  }
	}
      }
      if (i == asizeof(Locale->month))
	return 0;

      tm->tm_mon = i;
      buf += len;
      break;

    case 'm':
      if (!isdigit((unsigned char)*buf))
	return 0;

      len = 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (i < 1 || i > 12)
	return 0;

      tm->tm_mon = i - 1;

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'Y':
    case 'y':
      if (*buf == 0 || isspace((unsigned char)*buf))
	break;

      if (!isdigit((unsigned char)*buf))
	return 0;

      len = (c == 'Y') ? 4 : 2;
      for (i = 0; len && *buf != 0 && isdigit((unsigned char)*buf); buf++) {
	i *= 10;
	i += *buf - '0';
	len--;
      }
      if (c == 'Y')
	i -= 1900;
      if (c == 'y' && i < 69)
	i += 100;
      if (i < 0)
	return 0;

      tm->tm_year = i;

      if (*buf != 0 && isspace((unsigned char)*buf))
	while (*ptr != 0 && !isspace((unsigned char)*ptr))
	  ptr++;
      break;

    case 'Z':
      {
	const char *cp;
	char *zonestr;

	for (cp = buf; *cp && isupper((unsigned char)*cp); ++cp) 
	  {/*empty*/}
	if (cp - buf) {
	  zonestr = alloca(cp - buf + 1);
	  strncpy(zonestr, buf, cp - buf);
	  zonestr[cp - buf] = '\0';
	  tzset();
	  if (0 == strcmp(zonestr, "GMT")) {
	    got_GMT = 1;
	  } else {
	    return 0;
	  }
	  buf += cp - buf;
	}
      }
      break;
    }
  }
  return (char *)buf;
}


char *
strptime(const char *buf, const char *fmt, struct tm *tm)
{
  char *ret;

  got_GMT = 0;
  ret = _strptime(buf, fmt, tm);

  return ret;
}

/* ********************************* */

static const char *
inet_ntop4(src, dst, size)
     const u_char *src;
     char *dst;
     size_t size;
{
  static const char fmt[] = "%u.%u.%u.%u";
  char tmp[sizeof "255.255.255.255"];
  int nprinted;

  nprinted = safe_snprintf(__FILE__, __LINE__, tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
  if (nprinted < 0)
    return (NULL);  /* we assume "errno" was set by "snprintf()" */
  if ((size_t)nprinted > size) {
    errno = ENOSPC;
    return (NULL);
  }
  strcpy(dst, tmp);
  return (dst);
}

#define NS_IN6ADDRSZ 16

static const char *inet_ntop6(const u_char *src, char *dst, size_t size) {
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  char tmp[64], *tp;
  struct { int base, len; } best, cur;
  u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
  int i;

  memset(tmp, 0, sizeof(tmp));

  /*
   * Preprocess:
   *      Copy the input (bytewise) array into a wordwise array.
   *      Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, '\0', sizeof words);
  for (i = 0; i < NS_IN6ADDRSZ; i++)
    words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
  best.base = -1;
  cur.base = -1;
  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    if (words[i] == 0) {
      if (cur.base == -1)
	cur.base = i, cur.len = 1;
      else
	cur.len++;
    } else {
      if (cur.base != -1) {
	if (best.base == -1 || cur.len > best.len)
	  best = cur;
	cur.base = -1;
      }
    }
  }
  if (cur.base != -1) {

    if (best.base == -1 || cur.len > best.len)
      best = cur;
  }
  if (best.base != -1 && best.len < 2)
    best.base = -1;

  /*
   * Format the result.
   */
  tp = tmp;

  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    /* Are we inside the best run of 0x00's? */
    if (best.base != -1 && i >= best.base &&
	i < (best.base + best.len)) {
      if (i == best.base)
	*tp++ = ':';
      continue;
    }
    /* Are we following an initial run of 0x00s or any real hex? */
    if (i != 0)
      *tp++ = ':';
    /* Is this address an encapsulated IPv4? */
    if (i == 6 && best.base == 0 &&
	(best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
      if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
	return (NULL);
      tp += strlen(tp);
      break;
    }
    tp += safe_snprintf(__FILE__, __LINE__, tp, sizeof(tmp), "%x", words[i]);
  }

  /* Was it a trailing run of 0x00's? */
  if (best.base != -1 && (best.base + best.len) ==
      (NS_IN6ADDRSZ / NS_INT16SZ))
    *tp++ = ':';
  *tp++ = '\0';

  /*
   * Check for overflow, copy, and we're done.
   */
  if ((size_t)(tp - tmp) > size) {
    errno = ENOSPC;
    return (NULL);
  }
  strcpy(dst, tmp);
  return (dst);
}

PCSTR
WSAAPI
inet_ntop(
	  __in                                INT             af,
	  __in                                PVOID           src,
	  __out_ecount(StringBufSize)         PSTR            dst,
	  __in                                size_t          size
	  ){
  switch (af) {
  case AF_INET:
    return (inet_ntop4(src, dst, size));
  case AF_INET6:
    return (inet_ntop6(src, dst, size));
  default:
    errno = -1;
    return (NULL);
  }
  /* NOTREACHED */
}

/* ************************************************** */

int setenv(char *key, char *value, int mode) {
  char str[256];

  snprintf(str, sizeof(str), "%s=%s", key, value);
  return(putenv(str));
}
