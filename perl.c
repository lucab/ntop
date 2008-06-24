/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 * Copyright (C) 2008 Luca Deri <deri@ntop.org>
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


#include "ntop.h"
#include "globals-report.h"



#ifdef HAVE_PERL

#include "perl/ntop_perl.h"
#include "perl/ntop_wrap.c"

#if 0
#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */
#endif

PerlInterpreter *my_perl;  /***    The Perl interpreter    ***/

static HostTraffic *perl_host = NULL;
static HV * ss = NULL;

/*
  perl -MExtUtils::Embed -e xsinit -- -o perlxsi.c
*/
EXTERN_C void xs_init (pTHX);
EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);

EXTERN_C void xs_init(pTHX) {
  char *file = __FILE__;
  dXSUB_SYS;
  
  /* DynaLoader is a special case */
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}

/* *********************************************************** */

void ntop_perl_sendString(char *str) { 
  if(str && (strlen(str) > 0))
    _sendString(str, 1); 
}

/* *********************************************************** */

void ntop_perl_send_http_header(char *title) {
  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 0); 
  if(title && (strlen(title) > 0)) printHTMLheader(title, NULL, 0);
}

/* *********************************************************** */

void ntop_perl_send_html_footer() {
  printHTMLtrailer();
}

/* *********************************************************** */

#define PERL_STORE_STRING(a, b) hv_store(ss, a, strlen(a), newSVpv(b, strlen(b)), 0);
#define PERL_STORE_NUM(a, b)    { safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", b); PERL_STORE_STRING(a, buf); }

void ntop_perl_loadHost() {
  char buf[64];

  traceEvent(CONST_TRACE_INFO, "[perl] loadHost()");

  if(ss) {
    hv_undef(ss);
    ss = NULL;
  }

  if(perl_host) {
    ss = perl_get_hv ("main::host", TRUE);
    
    PERL_STORE_STRING("ethAddress", perl_host->ethAddressString);
    PERL_STORE_STRING("ipAddress", perl_host->hostNumIpAddress);
    PERL_STORE_STRING("hostResolvedName", perl_host->hostResolvedName);
    PERL_STORE_NUM("vlanId", perl_host->vlanId);
    PERL_STORE_NUM("hostAS", perl_host->hostAS);
    PERL_STORE_NUM("pktSent", perl_host->pktSent.value); PERL_STORE_NUM("pktRcvd", perl_host->pktRcvd.value);
    PERL_STORE_NUM("bytesSent", perl_host->bytesSent.value); PERL_STORE_NUM("bytesRcvd", perl_host->bytesRcvd.value);

  }
}

/* *********************************************************** */

void ntop_perl_getFirstHost(int actualDeviceId) { 
  perl_host = getFirstHost(actualDeviceId);

  traceEvent(CONST_TRACE_INFO, "[perl] getFirstHost(%d)=%p",
	     actualDeviceId, perl_host);
}

/* *********************************************************** */

void ntop_perl_getNextHost(int actualDeviceId) {
  if(perl_host == NULL) {
    ntop_perl_getFirstHost(actualDeviceId);
  } else {
    perl_host = getNextHost(actualDeviceId, perl_host);
  }

  traceEvent(CONST_TRACE_INFO, "[perl] getNextHost()=%p", perl_host);
}

/* *********************************************************** */

HostTraffic* ntop_perl_findHostByNumIP(HostAddr hostIpAddress, 
				       short vlanId, int actualDeviceId) {
  return(findHostByNumIP(hostIpAddress, vlanId, actualDeviceId));

}

/* *********************************************************** */

HostTraffic* ntop_perl_findHostBySerial(HostSerial serial, 
					int actualDeviceId) {
  return(findHostBySerial(serial, actualDeviceId));
}

/* *********************************************************** */

HostTraffic* ntop_perl_findHostByMAC(char* macAddr, 
				     short vlanId, int actualDeviceId) {
  return(findHostByMAC(macAddr, vlanId, actualDeviceId));
}

/* *********************************************************** */

/* http://localhost:3000/perl/test.pl */

int handlePerlHTTPRequest(char *url) {
  int perl_argc = 2;
  char perl_path[256];
  char * perl_argv[] = { "", NULL };

  traceEvent(CONST_TRACE_WARNING, "Calling perl... [%s]", url); 

  safe_snprintf(__FILE__, __LINE__, perl_path, sizeof(perl_path), "./perl/%s", url);
  perl_argv[1] = perl_path;

  PERL_SYS_INIT3(&argc, &argv, &env);
  if((my_perl = perl_alloc()) == NULL) {
    traceEvent(CONST_TRACE_WARNING, "[perl] Not enough memory");
    return(0);
  }

  perl_construct(my_perl);
  PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
  perl_parse(my_perl, xs_init, perl_argc, perl_argv, (char **)NULL);

  SWIG_InitializeModule(0);
  newXS("sendString", _wrap_ntop_perl_sendString, (char*)__FILE__);
  newXS("send_http_header", _wrap_ntop_perl_send_http_header, (char*)__FILE__);
  newXS("send_html_footer", _wrap_ntop_perl_send_html_footer, (char*)__FILE__);
  newXS("loadHost", _wrap_ntop_perl_loadHost, (char*)__FILE__);
  newXS("getFirstHost", _wrap_ntop_perl_getFirstHost, (char*)__FILE__);
  newXS("getNextHost", _wrap_ntop_perl_getNextHost, (char*)__FILE__);

  perl_run(my_perl);

  PL_perl_destruct_level = 0;
  perl_destruct(my_perl);
  perl_free(my_perl);
  PERL_SYS_TERM();
  return(1);
}



#endif /* HAVE_PERL */
