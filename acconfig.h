/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * Custom Ntop defines, the meat for 'autoconf'
 *
 * Copyright (c) 1998-2001 Luca Deri <deri@ntop.org>
 * Updated 1Q 2000 Rocco Carbone <rocco@ntop.org>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */


#ifndef _CONFIG_H_
#define _CONFIG_H_


/* insert here custom defines */

/* Define if you want to build micro ntop. */
#undef MICRO_NTOP

/* Define if you want to build with MySQL support. */
#undef HAVE_MYSQL

/* Define if you want a debugging version. */
#undef DEBUG

/* Define if you OS lacks the getdomainname(2) function. */
#undef NEED_GETDOMAINNAME

/* Define to have essential fallback. */
#undef HAVE_U_INT32_T
#undef HAVE_U_INT16_T
#undef HAVE_U_INT8_T
#undef HAVE_INT32_T
#undef HAVE_INT16_T
#undef HAVE_INT8_T
#undef u_int


#undef RETSIGTYPE

/* Define if you have the <gdbm.h> header file. */
#undef HAVE_GDBM_H

/* Define if the ether_header uses ether_addr structs. */
#undef ETHER_HEADER_HAS_EA

/* Define if you have the thread library (-lpthread). */
#undef HAVE_LIBTHREAD

/* Define if you have the OPENSSL Toolkit (-lssl) by Open SSL Project. */
#undef HAVE_OPENSSL

/* Define if you want to have a asyncrhonous address resolution. */
#undef ASYNC_ADDRESS_RESOLUTION

/* Define if you want to have a multithreaded version of ntop. */
#undef MULTITHREADED

/* Define if you have the curses library (-lncurses or -lcurses). */
#undef HAVE_LIBCURSES

/* Define if you have the ncurses.h or curses.h header files (specific to handle Solaris 2.7) */
#undef HAVE_NCURSES_H
#undef HAVE_CURSES_H

/* Define if you have the TCP Wrap library (-lwrap). */
#undef HAVE_LIBWRAP

/* Define if you have the GNU readline library (-lreadline). */
#undef HAVE_READLINE

/* Define if you need a private implementation of inet_aton (solaris 2.5.1 doesn't have it). */
#undef NEED_INET_ATON

/* Define if you have the regex lib defined inside libc */
#undef HAVE_REGEX

/* Define if you have the gdchart library from Bruce Verderaime [http://www.fred.net/brv/chart/]. */
#undef HAVE_GDCHART

/* Define if you have the zlib */
#undef HAVE_ZLIB

/* Ntop directories */
#undef PLUGIN_DIR
#undef DATAFILE_DIR
#undef CONFIGFILE_DIR
#undef DBFILE_DIR

/* Define if your host supports SNMP  */
#undef HAVE_SNMP


#endif /* _CONFIG_H_ */
