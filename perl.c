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
//#include "globals-report.h"

#ifdef HAVE_PERL

#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */
PerlInterpreter *my_perl;  /***    The Perl interpreter    ***/


/* http://localhost:3000/perl/test.pl */

int handlePerlHTTPRequest(char *url) {
  int perl_argc = 2;
  char * perl_argv [] = { "", "./perl/test.pl" };
  HV * ss = NULL;       /* the @sorttypes */

  traceEvent(CONST_TRACE_WARNING, "Calling perl...");

  PERL_SYS_INIT3(&argc,&argv,&env);
  my_perl = perl_alloc();
  perl_construct(my_perl);
  PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
  perl_parse(my_perl, NULL, perl_argc, perl_argv, (char **)NULL);

  ss = perl_get_hv ("main::myhost", TRUE);
  
  hv_store(ss, "name", strlen ("name"), newSVpv ("xxx", strlen ("xxx")), 0);
  hv_store(ss, "ip", strlen ("ip"), newSVpv ("1.2.3.4", strlen ("1.2.3.4")), 0);
  

  perl_run(my_perl);
  hv_undef(ss);
  perl_destruct(my_perl);
  perl_free(my_perl);
  PERL_SYS_TERM();
  return(1);
}



#endif /* HAVE_PERL */
