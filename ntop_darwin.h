/*
 *  Copyright (C) 2001-12  Luca Deri <deri@ntop.org>
 *
 *  			   http://www.ntop.org/
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

/* 
   This file contains some compatibility functions that are needed for
   ntop to run on Darwin/MacOS X
*/

#ifdef DARWIN

/* ***************************************************************** */

/*
 * This file was modified by Christoph Pfisterer <cp@chrisp.de>
 * on Sat, May 5 2001. See the file "ChangeLog" for details of what
 * was changed.
 *
 *
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifdef __cplusplus
extern "C" {
#endif

extern void * dlopen(
    const char *path,
    int mode);
extern void * dlsym(
    void * handle,
    const char *symbol);
extern const char * dlerror(
    void);
extern int dlclose(
    void * handle);

#define RTLD_LAZY	0x1
#define RTLD_NOW	0x2
#define RTLD_LOCAL	0x4
#define RTLD_GLOBAL	0x8
#define RTLD_NOLOAD	0x10
#define RTLD_SHARED	0x20	/* not used, the default */
#define RTLD_UNSHARED	0x40
#define RTLD_NODELETE	0x80
#define RTLD_LAZY_UNDEF	0x100

#ifdef __cplusplus
}
#endif

/* ***************************************************************** */

#endif /* DARWIN */
