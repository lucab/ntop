/**
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2005 Burton Strauss <burton@ntopsupport.com>
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*

 A bit ugly...

  dlfcn is referenced in ntop.h, w/o the __USE_GNU (i.e. w/o the GNU
  extensions).  In FreeBSD it doesn't matter, but for Linux it does.
  I don't want to chase that bug-a-boo, but I do need the extension
  so dladdr is available.

  Hence this special routine w __USE_GNU and w/o ntop.h


  If you need anything from regular ntop, remember we don't have ntop.h,
  so you will have to copy the things you need from globals-defines.h and
  globals-core.h

 */

#ifndef WIN32

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
 
#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <dlfcn.h>

#include "config.h"

/* Forward */
int getDynamicLoadPaths(char *main, int mainLen, char *lib, int libLen, char *env, int envLen);

/* Copied declarations */

extern void welcome(FILE * fp);

#define safe_strncat(a, b, c) _safe_strncat(__FILE__, __LINE__, a, b, c)
extern int _safe_strncat(char* file, int line,
                         char* dest, size_t sizeofdest,
                         char* src);

//extern void traceEvent(int eventTraceLevel, char* file,
//                       int line, char * format, ...)
//     __attribute__ ((format (printf, 4, 5)));

/*
 * Used in traceEvent()
 */
//#define CONST_ALWAYSDISPLAY_TRACE_LEVEL     -1
//#define CONST_FATALERROR_TRACE_LEVEL        0
//#define CONST_ERROR_TRACE_LEVEL             1
//#define CONST_WARNING_TRACE_LEVEL           2
//#define CONST_INFO_TRACE_LEVEL              3
//#define CONST_NOISY_TRACE_LEVEL             4

//#define CONST_TRACE_ALWAYSDISPLAY           CONST_ALWAYSDISPLAY_TRACE_LEVEL, __FILE__, __LINE__
//#define CONST_TRACE_FATALERROR              CONST_FATALERROR_TRACE_LEVEL, __FILE__, __LINE__
//#define CONST_TRACE_ERROR                   CONST_ERROR_TRACE_LEVEL, __FILE__, __LINE__
//#define CONST_TRACE_WARNING                 CONST_WARNING_TRACE_LEVEL, __FILE__, __LINE__
//#define CONST_TRACE_INFO                    CONST_INFO_TRACE_LEVEL, __FILE__, __LINE__
//#define CONST_TRACE_NOISY                   CONST_NOISY_TRACE_LEVEL, __FILE__, __LINE__

/* ************************************************************************ */

int getDynamicLoadPaths(char *main, int mainLen, char *lib, int libLen, char *env, int envLen) {
  int rc = 0;

#ifdef HAVE_DLADDR
  char *lastslash, *_env;
  Dl_info info;

  memset(main, 0, mainLen);
  memset(lib, 0, libLen);
  memset(env, 0, envLen);
  memset(&info, 0, sizeof(info));

  rc = dladdr((void *)&welcome, &info);
  if(rc == 0)
    return(-2);

  strncpy(main, info.dli_fname, mainLen);
  lastslash = strrchr(main, '/');
  if(lastslash != NULL) lastslash[0] = '\0';

  rc = dladdr((void *)&getDynamicLoadPaths, &info);
  if(rc == 0)
    return(-3);

  strncpy(lib, info.dli_fname, libLen);
  lastslash = strrchr(lib, '/');
  if(lastslash != NULL) lastslash[0] = '\0';

#ifdef DARWIN
  _env = getenv("DYLD_LIBRARY_PATH");
  if((_env != NULL) && (_env[0] != '\0')) {
    strncpy(env, "DYLD_LIBRARY_PATH: ", envLen);
    safe_strncat(env, envLen, _env);
  }
#endif
  _env = getenv("LD_LIBRARY_PATH");
  if((_env != NULL) && (_env[0] != '\0')) {
    safe_strncat(env, envLen, "LD_LIBRARY_PATH ");
    safe_strncat(env, envLen, _env);
  }

  return(0);

#else

  return(-1); /* "failed" */

#endif /* HAVE_DLADDR */

}

#endif /* WIN32 */
