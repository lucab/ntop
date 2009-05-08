/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *             Copyright (C) 2008-09 Luca Deri <deri@ntop.org>
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

static HostTraffic *ntop_host = NULL;
static HV * perl_host = NULL;
static HV * ss_hosts = NULL;

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

void ntop_perl_send_http_header(int mime_type, char *title) {
  sendHTTPHeader(mime_type /* FLAG_HTTP_TYPE_HTML */, 0, 0);
  if(title && (strlen(title) > 0)) printHTMLheader(title, NULL, 0);
}

/* *********************************************************** */

void ntop_perl_sendFile(char* fileName, int doNotUnlink) {
  sendFile(fileName, doNotUnlink);
}

/* *********************************************************** */

void ntop_perl_send_html_footer() {
  printHTMLtrailer();
}

/* *********************************************************** */

#define PERL_STORE_STRING(x, a, b) hv_store(x, a, strlen(a), newSVpv(b, strlen(b)), 0);
#define PERL_STORE_NUM(x, a, b)    { char buf[64]; safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", b); PERL_STORE_STRING(x, a, buf); }

static void ntop_perl_loadHost_values(HV * my_ss, HostTraffic *host) {
  /* traceEvent(CONST_TRACE_INFO, "[perl] loadHost_values()"); */

  PERL_STORE_STRING(my_ss, "ethAddress", host->ethAddressString);
  PERL_STORE_STRING(my_ss, "ipAddress", host->hostNumIpAddress);
  PERL_STORE_STRING(my_ss, "hostResolvedName", host->hostResolvedName);
  PERL_STORE_NUM(my_ss, "vlanId", host->vlanId);
  PERL_STORE_NUM(my_ss, "hostAS", host->hostAS);
  PERL_STORE_NUM(my_ss, "pktSent", host->pktSent.value);
  PERL_STORE_NUM(my_ss, "pktRcvd", host->pktRcvd.value);
  PERL_STORE_NUM(my_ss, "bytesSent", host->bytesSent.value);
  PERL_STORE_NUM(my_ss, "bytesRcvd", host->bytesRcvd.value);
}

/* *********************************************************** */

void ntop_perl_loadHost() {
  char buf[64];

  /* traceEvent(CONST_TRACE_INFO, "[perl] loadHost(%p)", ntop_host); */

  if(perl_host) {
    hv_undef(perl_host);
    perl_host = NULL;
  }

  if(ntop_host) {
    perl_host = perl_get_hv ("main::host", TRUE);
    ntop_perl_loadHost_values(perl_host, ntop_host);
  }
}

/* *********************************************************** */

void ntop_perl_getFirstHost(int actualDeviceId) {
  ntop_host = getFirstHost(actualDeviceId);

  /*
  traceEvent(CONST_TRACE_INFO, "[perl] getFirstHost(%d)=%p",
	     actualDeviceId, ntop_host);
  */
}

/* *********************************************************** */

void ntop_perl_getNextHost(int actualDeviceId) {
  if(ntop_host == NULL) {
    ntop_perl_getFirstHost(actualDeviceId);
  } else {
    ntop_host = getNextHost(actualDeviceId, ntop_host);
  }

  /* traceEvent(CONST_TRACE_INFO, "[perl] getNextHost()=%p", ntop_host); */
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
  int perl_argc = 2, idx, found = 0;
  char perl_path[256];
  char * perl_argv[] = { "", NULL };
  struct stat statbuf;
  char *question_mark = strchr(url, '?');
  PerlInterpreter *my_perl;  /***    The Perl interpreter    ***/

  traceEvent(CONST_TRACE_WARNING, "Calling perl... [%s]", url);

  if(question_mark) question_mark[0] = '\0';

  for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
  safe_snprintf(__FILE__, __LINE__, perl_path, sizeof(perl_path), 
	  "%s/perl/%s", myGlobals.dataFileDirs[idx], url);
    revertSlashIfWIN32(perl_path, 0);

    if(!stat(perl_path, &statbuf)) {
      /* Found */
      /* traceEvent(CONST_TRACE_INFO, "[perl] [%d] Found %s", idx, perl_path); */
      found = 1;
      break;
    } else {
      /* traceEvent(CONST_TRACE_INFO, "[perl] [%d] Not found %s", idx, perl_path); */
    }
  }

  if(!found) {
    returnHTTPpageNotFound(NULL);
    return(1);
  }

  perl_argv[1] = perl_path;

  PERL_SYS_INIT(&perl_argc, &perl_argv);
  if((my_perl = perl_alloc()) == NULL) {
    traceEvent(CONST_TRACE_WARNING, "[perl] Not enough memory");
    return(0);
  }

  perl_construct(my_perl);
  PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
  perl_parse(my_perl, xs_init, perl_argc, perl_argv, (char **)NULL);

  SWIG_InitializeModule(0);

  if(question_mark) {
    PERL_STORE_STRING(perl_get_hv("main::ENV", TRUE), "QUERY_STRING_UNESCAPED", &question_mark[1]);
  } 

  newXS("sendString", _wrap_ntop_perl_sendString, (char*)__FILE__);
  newXS("sendFile", _wrap_ntop_perl_sendFile, (char*)__FILE__);
  newXS("send_http_header", _wrap_ntop_perl_send_http_header, (char*)__FILE__);
  newXS("send_html_footer", _wrap_ntop_perl_send_html_footer, (char*)__FILE__);
  newXS("loadHost", _wrap_ntop_perl_loadHost, (char*)__FILE__);
  newXS("getFirstHost", _wrap_ntop_perl_getFirstHost, (char*)__FILE__);
  newXS("getNextHost", _wrap_ntop_perl_getNextHost, (char*)__FILE__);

  perl_run(my_perl);

  /* Unset variables */
  perl_host = NULL;

  // PL_perl_destruct_level = 1;
  perl_destruct(my_perl);
  perl_free(my_perl);
  //PERL_SYS_TERM();
  return(1);
}



#endif /* HAVE_PERL */
