/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *                      
 *			    http://www.ntop.org/
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

#include "ntop.h"
#include "globals-report.h"


#ifndef MICRO_NTOP

/* Forward */
#ifdef HAVE_GDBM_H
static void sendMenuFooter(int itm1Idx, int itm2Idx);
static void encodeWebFormURL(char *in, char *buf, int buflen);
static void decodeWebFormURL(char *buf);
static int readHTTPpostData(int len, char *buf, int buflen);
#endif

/* *******************************/

#ifdef HAVE_GDBM_H
void showUsers(void) {
  u_int numUsers=0;
  char buf[BUF_SIZE], ebuf[128];
  datum key_data, return_data;

  printHTMLheader("Registered ntop Users", HTML_FLAG_NO_REFRESH);
  sendString("<P><HR><P>\n");

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "showUsers");
#endif 
  return_data = gdbm_firstkey (pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(TRACE_INFO, "1) -> %s\n", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '1') /* 1 = user */{

      if(numUsers == 0) {
	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1>\n");
	sendString("<TR><TH "TH_BG">Users</TH><TH "TH_BG">Actions</TH></TR>\n");
      }

      if(strcmp(key_data.dptr, "1admin") == 0) {
	if(snprintf(buf, BUF_SIZE, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
		"&nbsp;%s</TH><TD "TD_BG"><A HREF=/modifyUser?%s>"
		"<IMG SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		"&nbsp;</TD></TR></TH></TR>\n", &key_data.dptr[1], key_data.dptr) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      } else{
	encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));
	if(snprintf(buf, BUF_SIZE, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
		"&nbsp;%s</TH><TD "TD_BG"><A HREF=/modifyUser?%s>"
		"<IMG SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		"&nbsp;<A HREF=/deleteUser?%s><IMG SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
		"</A></TD></TR></TH></TR>\n", &key_data.dptr[1], ebuf, ebuf) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      }
      sendString(buf);
      numUsers++;
    }

    return_data = gdbm_nextkey(pwFile, key_data);
    free(key_data.dptr);
  }
    
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  if(numUsers > 0) {
    sendString("</TABLE>"TABLE_OFF"\n<P>\n");
    sendString("</CENTER>\n");
  }
  sendMenuFooter(1, 2);
}

/* *******************************/

void addUser(char* user) {
  char tmpStr[128];
    
  printHTMLheader("Manage ntop Users", HTML_FLAG_NO_REFRESH);
  sendString("<P><HR><P>\n");

  if((user != NULL) && ((strlen(user) < 2) || (user[0] != '1'))) {
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    sendString("<CENTER>\n");
    sendString("<FORM METHOD=POST ACTION=/doAddUser>\n");

    sendString("<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=5>\n");
    sendString("<TR>\n<TH ALIGN=right>User:&nbsp;</TH><TD ALIGN=left>");
    if(user != NULL) {
      decodeWebFormURL(user);
      if(snprintf(tmpStr, sizeof(tmpStr),
	     "<INPUT TYPE=hidden NAME=user SIZE=20 VALUE=\"%s\"><B>%s</B>\n",
	     &user[1], &user[1]) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(tmpStr);
    } else
      sendString("<INPUT TYPE=text NAME=user SIZE=20>\n");
    sendString("</TD>\n</TR>\n");
    sendString("<TR>\n<TH ALIGN=right>Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw SIZE=20></TD></TR>\n");
    sendString("</TABLE>\n");

    if(snprintf(tmpStr, sizeof(tmpStr),
	   "<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset>\n",
	   (user != NULL) ? "Modify User" : "Add User") < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(tmpStr);

    sendString("</FORM>\n");
    sendString("</CENTER>\n");
  }
  sendMenuFooter(0, 2);
}

/* *******************************/

void deleteUser(char* user) {

  if(user == NULL) {
    returnHTTPredirect("showUsers.html");
    return;
  } else if((strlen(user) < 2) || (user[0] != '1')) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("Delete ntop User", HTML_FLAG_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    int rc;
    datum key_data;

    decodeWebFormURL(user);
    key_data.dptr = user;
    key_data.dsize = strlen(user)+1;
      
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "deleteUser");
#endif 
    rc = gdbm_delete (pwFile, key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 

    if(rc != 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("Delete ntop User", HTML_FLAG_NO_REFRESH);
      sendString("<P><HR><P>\n");
      printFlagedWarning("<B>ERROR:</B> <I>unable to delete specified user.</I>");
    } else {
      returnHTTPredirect("showUsers.html");
      return;
    }

  }
  sendMenuFooter(1, 2);
  printHTMLtrailer();
}
/* *******************************/

void doAddUser(int len) {
  char *err=NULL;

  if(len <= 0) {
    err = "ERROR: both user and password must be non empty fields.";
  } else {
    char postData[256], *key, *user=NULL, *pw=NULL;
    int i, idx, badChar=0;

    if((idx = readHTTPpostData(len, postData, sizeof(postData))) < 0)
      return; /* FIXME (DL): an HTTP error code should be sent here */

    for(i=0,key=postData; i<idx; i++) {
      if(postData[i] == '&') {
	postData[i] = '\0';
	key = &postData[i+1];
      } else if((key != NULL) && (postData[i] == '=')) {
	postData[i] = '\0';
	if(strcmp(key, "user") == 0)
	  user = &postData[i+1];
	else if(strcmp(key, "pw") == 0)
	  pw = &postData[i+1];
	key = NULL;
      }
    }
    if(user != NULL) {
      decodeWebFormURL(user);
      for(i=0; i<strlen(user); i++) {
	if(!(isalpha(user[i]) || isdigit(user[i]))) {
	  badChar = 1;
	  break;
	}
      }
    }
    if(pw != NULL)
      decodeWebFormURL(pw);

#if 0
    printf("User='%s' - Pw='%s'\n", user?user:"(not given)", pw?pw:"(not given)");
    fflush(stdout);
#endif

    if((user == NULL ) || (user[0] == '\0') || (pw == NULL) || (pw[0] == '\0')) {
      err = "ERROR: both user and password must be non empty fields.";
    } else if(badChar) {
      err = "ERROR: the specified user name contains invalid characters.";
    } else {
      char tmpBuf[64], cpw[14];
      datum data_data, key_data;

      if(snprintf(tmpBuf, sizeof(tmpBuf), "1%s", user) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      key_data.dptr = tmpBuf;
      key_data.dsize = strlen(tmpBuf)+1;
#ifdef WIN32
      data_data.dptr = pw;
#else
      strncpy(cpw, (char*)crypt(pw, (const char*)CRYPT_SALT), sizeof(cpw));
      cpw[sizeof(cpw)-1] = '\0';
      data_data.dptr = cpw;
#endif
      data_data.dsize = strlen(data_data.dptr)+1;
#ifdef DEBUG
      traceEvent(TRACE_INFO, "User='%s' - Pw='%s [%s]'\n", user, pw, data_data.dptr);
#endif

#ifdef MULTITHREADED
      accessMutex(&gdbmMutex, "doAddUser");
#endif 
      if(gdbm_store(pwFile, key_data, data_data, GDBM_REPLACE) != 0)
	err = "FATAL ERROR: unable to add the new user.";

#ifdef MULTITHREADED
      releaseMutex(&gdbmMutex);
#endif 
    }
  }

  if(err != NULL) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("ntop user add", HTML_FLAG_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning(err);
    sendMenuFooter(1, 2);
    printHTMLtrailer();
  } else {
    returnHTTPredirect("showUsers.html");
  }
}

/* ***********************************
   *********************************** */

void showURLs(void) {
  u_int numUsers=0;
  char buf[BUF_SIZE], ebuf[128];
  datum key_data, return_data;

  printHTMLheader("Restricted ntop URLs", HTML_FLAG_NO_REFRESH);
  sendString("<P><HR><P>\n");

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "showURLs");
#endif 
  return_data = gdbm_firstkey (pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(TRACE_INFO, "1) -> %s\n", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '2') { /* 2 = URL */

      if(numUsers == 0) {
	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=5>\n");
	sendString("<TR><TH "TH_BG">URLs</TH><TH "TH_BG">Actions</TH></TR>\n");
      }

      encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));
      if(snprintf(buf, BUF_SIZE, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
	      "&nbsp;'%s*'</TH><TD "TD_BG"><A HREF=/modifyURL?%s>"
	      "<IMG SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
	      "&nbsp;<A HREF=/deleteURL?%s><IMG SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
	      "</A></TD></TR></TH></TR>\n", &key_data.dptr[1], ebuf, ebuf) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(buf);
      numUsers++;      
    }

    return_data = gdbm_nextkey(pwFile, key_data);
    free(key_data.dptr);
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
    
  if(numUsers > 0) {
    sendString("</TABLE>"TABLE_OFF"\n<P>\n");
    sendString("</CENTER>\n");
  } 
  sendMenuFooter(3, 0);
}

/* *******************************/

void addURL(char* url) {
  int i;
  datum key_data, return_data;
  char *aubuf=NULL, *authorisedUser[20];
  char tmpStr[128];

  printHTMLheader("Manage ntop URLs", HTML_FLAG_NO_REFRESH);
  sendString("<P><HR><P>\n");

  if((url != NULL) && ((strlen(url) < 1) || (url[0] != '2'))) {
    printFlagedWarning("<I>The specified URL is invalid.</I>");

  } else {
    sendString("<CENTER>\n");
    sendString("<FORM METHOD=POST ACTION=/doAddURL>\n");

    sendString("<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=3>\n");
    if(url != NULL)
      sendString("<TR>\n<TH ALIGN=right VALIGN=top><B>URL</B>:&nbsp;</TH>");
    else
      sendString("<TR>\n<TH ALIGN=right VALIGN=middle><B>URL</B>:&nbsp;</TH>");
    sendString("<TD ALIGN=left><TT>http://&lt;"
	       "<I>ntop host</I>&gt;:&lt;<I>ntop port</I>&gt;/</TT>");
    if(url != NULL) {
      decodeWebFormURL(url);
      if(snprintf(tmpStr, sizeof(tmpStr),
	       "<INPUT TYPE=hidden NAME=url SIZE=20 VALUE=\"%s\">"
	       "<B>%s</B>&nbsp;<B>*</B>  [Initial URL string]",
	       &url[1], &url[1]) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
      sendString(tmpStr);
    } else {
      sendString("<INPUT TYPE=text NAME=url SIZE=20>&nbsp;*");
    }
    sendString("</TD>\n</TR>\n");
    sendString("<TR>\n<TH ALIGN=right VALIGN=top>Authorised Users:&nbsp;</TH>"
	       "<TD ALIGN=left><SELECT NAME=users MULTIPLE>\n");

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "addURL");
#endif 
  
    authorisedUser[0] = NULL;
    if(url != NULL) {
      key_data.dptr = url;
      key_data.dsize = strlen(url)+1;
      return_data = gdbm_fetch(pwFile, key_data);

      if(return_data.dptr != NULL) {
	char *strtokState, *item;

	aubuf = return_data.dptr;
	item = strtok_r(aubuf, "&", &strtokState);
	for(i=0; (item != NULL) && (i < sizeof(authorisedUser)-1); i++) {
	  authorisedUser[i] = &item[sizeof("users=")-1];
	  item = strtok_r(NULL, "&", &strtokState);
	}
	if(item != NULL) {
	  traceEvent(TRACE_ERROR, "Too many users for URL='%s'\n", url);
	} 
	authorisedUser[i] = NULL;
      }
    }

    return_data = gdbm_firstkey(pwFile);

    while (return_data.dptr != NULL) {
      key_data = return_data;

      if(key_data.dptr[0] == '1') { /* 1 = user */
	int found = 0;

	for(i=0; authorisedUser[i] != NULL; i++) {
	  if(strcmp(authorisedUser[i], key_data.dptr) == 0)
	    found = 1;
	}
        if(snprintf(tmpStr, sizeof(tmpStr),
	         "<OPTION VALUE=%s %s>%s", 
	         key_data.dptr, found ? "SELECTED" : "", &key_data.dptr[1]) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
        sendString(tmpStr);
      }

      return_data = gdbm_nextkey(pwFile, key_data);
      free(key_data.dptr);
    }

    if(aubuf != NULL)
      free(aubuf);

#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 

    sendString("</SELECT>\n</TD></TR>\n");
    sendString("</TABLE>\n");

    if(url == NULL)
      sendString("<BLOCKQUOTE>\n<DIV ALIGN=left>\n"
		 "<B><U>NOTE</U>: if you leave the URL field empty then the "
		 "access is restricted to <I>all</I> ntop pages, otherwise, this "
		 "entry matches all the pages begining with the specified string.</B>\n"
		 "</DIV>\n</BLOCKQUOTE>\n");

    if(snprintf(tmpStr, sizeof(tmpStr),
	     "<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset>\n",
	     (url != NULL) ? "Modify URL" : "Add URL") < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
    sendString(tmpStr);

    sendString("</FORM>\n");
    sendString("</CENTER>\n");

  }
  sendMenuFooter(0, 2);
}

/* *******************************/

void deleteURL(char* url) {

  if(url == NULL) {
    returnHTTPredirect("showURLs.html");
    return;
  } else if((strlen(url) < 1) || (url[0] != '2')) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("Delete ntop URL", HTML_FLAG_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning("<I>The specified URL is invalid.</I>");
  } else {
    int rc;
    datum key_data;

    decodeWebFormURL(url);
    key_data.dptr = url;
    key_data.dsize = strlen(url)+1;

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "deleteURL");
#endif 
    rc = gdbm_delete (pwFile, key_data);
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 

    if(rc != 0) {
      sendHTTPHeader(HTTP_TYPE_HTML, 0);
      printHTMLheader("Delete ntop URL", HTML_FLAG_NO_REFRESH);
      sendString("<P><HR><P>\n");
      printFlagedWarning("<B>ERROR:</B> <I>unable to delete specified URL.</I>");
    } else {
      returnHTTPredirect("showURLs.html");
      return;
    }

  }
  sendMenuFooter(3, 0);
  printHTMLtrailer();
}

/* *******************************/

void doAddURL(int len) {
  char *err=NULL;
  char postData[256], *key, *url=NULL, *users=NULL, authorizedUsers[256];
  int i, idx, alen=0, badChar=0;

  /*
    Authorization fix
    courtesy of David Brown <david@caldera.com>
  */

  if((idx = readHTTPpostData(len, postData, sizeof(postData))) < 0)
    return; /* FIXME (DL): an HTTP error code should be sent here */

  memset(authorizedUsers, 0, sizeof(authorizedUsers));
  for(i=0,key=postData; i<=idx; i++) {
    if((i==idx) || (postData[i] == '&')) {
      if(users != NULL) {
	decodeWebFormURL(users);
	if(snprintf(&authorizedUsers[alen], sizeof(authorizedUsers)-alen,
		    "%susers=%s", (alen>0) ? "&" : "", users) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
	alen = strlen(authorizedUsers);
	users = NULL;
      }
      if(i==idx) break;
      postData[i] = '\0';
      key = &postData[i+1];
    } else if((key != NULL) && (postData[i] == '=')) {
      postData[i] = '\0';
      if(strcmp(key, "url") == 0) {
	url = &postData[i+1];
      } else if(strcmp(key, "users") == 0) {
	users = &postData[i+1];
      }
      key = NULL;
    }
  }
  if(url != NULL) {
    decodeWebFormURL(url);
    for(i=0; i<strlen(url); i++) {
      if(!(isalpha(url[i]) || isdigit(url[i]) || (strchr("/-_?", url[i]) != NULL))) {
	badChar = 1;
	break;
      }
    }
  }

#if 0
  printf("URL: '%s' - users: '%s'\n", url?url:"(not given)", strlen(authorizedUsers)>0?authorizedUsers:"(not given)"); 
  fflush(stdout);
#endif

  if(authorizedUsers[0] == '\0') {
    err = "ERROR: user must be a non empty field.";
  } else if(badChar) {
    err = "ERROR: the specified URL contains invalid characters.";
  } else {
    char tmpBuf[64];
    datum data_data, key_data;

    if(snprintf(tmpBuf, sizeof(tmpBuf), "2%s", url) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");
    key_data.dptr = tmpBuf;
    key_data.dsize = strlen(tmpBuf)+1;
    data_data.dptr = authorizedUsers;
    data_data.dsize = strlen(authorizedUsers)+1;
    
#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "doAddURL");
#endif 
    if(gdbm_store(pwFile, key_data, data_data, GDBM_REPLACE) != 0)
      err = "FATAL ERROR: unable to add the new URL.";
#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 
  }
#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  if(err != NULL) {
    sendHTTPHeader(HTTP_TYPE_HTML, 0);
    printHTMLheader("ntop URL add", HTML_FLAG_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning(err);
    sendMenuFooter(3, 0);
    printHTMLtrailer();
  } else {
    returnHTTPredirect("showURLs.html");
  }
}

/* *******************************/

struct _menuData {
  char	*text, *anchor;
};

static struct _menuData menuItem[] = {
  { "Show Users", "showUsers" },
  { "Add User",   "addUser" },
  { "Show URLs",  "showURLs" },
  { "Add URL",    "addURL" }
};

/* *******************************/

static void sendMenuFooter(int itm1Idx, int itm2Idx) {
  char	buf[128];

  sendString("<CENTER>\n");
  sendString("<H4><FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");
  if(snprintf(buf, sizeof(buf),
	     "[<A HREF=/%s.html>%s</A>]&nbsp;[<A HREF=/%s.html>%s</A>]\n",
	     menuItem[itm1Idx].anchor, menuItem[itm1Idx].text,
	     menuItem[itm2Idx].anchor, menuItem[itm2Idx].text) < 0) 
	  traceEvent(TRACE_ERROR, "Buffer overflow!");
  sendString(buf);
  sendString("</FONT></H4>\n");
  sendString("</CENTER>\n");

}

/* *******************************/
static void encodeWebFormURL(char *in, char *buf, int buflen) {
  int i, j, c, d;

  for(i=j=0; (in[i]!='\0') && (j<(buflen-4)); i++) {
    c = (unsigned int)in[i];
    if(isalpha(c) || isdigit(c)) {
      buf[j++] = (char)c;
    } else if (c == ' ') {
      buf[j++] = '+';
    } else {
      buf[j++] = '%';
      d = (c>>4) & 0x0f;
      buf[j++] = (d < 10) ? '0'+d : 'A'+(d-10);
      d = c & 0x0f;
      buf[j++] = (d < 10) ? '0'+d : 'A'+(d-10);
    }
  }
  buf[j] = '\0';
}

/* *******************************/
static void decodeWebFormURL(char *buf) {
  int i, j;

  for(i=j=0; buf[i]!='\0'; i++,j++) {
    buf[j] = buf[i];
    if(buf[j] == '+') {
      buf[j] = ' ';
    } else if(buf[j] == '%') {
      buf[j] = ((buf[i+1] >= 'A' ? ((buf[i+1] & 0xdf) - 'A')+10 : (buf[i+1] - '0')) & 0x0f) << 4 | 
               ((buf[i+2] >= 'A' ? ((buf[i+2] & 0xdf) - 'A')+10 : (buf[i+2] - '0')) & 0x0f);
      i += 2;
    }
  }
  buf[j] = '\0';
}

/* *******************************/
static int readHTTPpostData(int len, char *buf, int buflen) {
  int rc, idx=0;

#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-newSock);
#endif

  memset(buf, 0, buflen);

  if(len > (buflen-8)) {
    traceEvent(TRACE_ERROR, "Too much HTTP POST data");
    return (-1);
  }

  while(len > 0) {
#ifdef HAVE_OPENSSL
    if(newSock < 0) 
      rc = SSL_read(ssl, &buf[idx], len);
    else
      rc = recv(newSock, &buf[idx], len, 0);
#else
    rc = recv(newSock, &buf[idx], len, 0);
#endif
    if(rc < 0)
      return (-1);

    idx += rc;
    len -= rc;
  }

  buf[idx] = '\0';
  
  while(1) {
    fd_set mask;
    struct timeval wait_time;

    FD_ZERO(&mask);
    FD_SET((unsigned int)abs(newSock), &mask);    
  
    /* select returns immediately */
    wait_time.tv_sec = 0, wait_time.tv_usec = 0; 
    if(select(newSock+1, &mask, 0, 0, &wait_time) == 1) {
      char aChar[8]; /* just in case */

#ifdef HAVE_OPENSSL
      if(newSock < 0) 
	rc = SSL_read(ssl, aChar, 1);
      else
	rc = recv(newSock, aChar, 1, 0);
#else
      rc = recv(newSock, aChar, 1, 0);
#endif
      if(rc <= 0)
	break;
    } else
      break;
  }

#if 0
  printf("HTTP POST data: '%s' (%d)\n", buf, idx); 
  fflush(stdout);
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "Data: '%s' (%d)\n", buf, idx); 
#endif

  return (idx);
}

#endif /* HAVE_GDBM_H */
#endif /* MICRO_NTOP */

/* *******************************/

static void addKeyIfMissing(char* key, char* value, int encryptValue) {
  datum key_data, return_data, data_data;
  char cpw[14];

  /* Check existence of user 'admin' */
  key_data.dptr = key;
  key_data.dsize = strlen(key_data.dptr)+1;
  return_data = gdbm_fetch(pwFile, key_data);

  if(return_data.dptr == NULL) {
    /* If not existing, the add user 'admin', pw 'admin' */
    if(encryptValue) {
#ifdef WIN32
      data_data.dptr = value;
#else
      strncpy(cpw, (char*)crypt(value, (const char*)CRYPT_SALT), sizeof(cpw));
      cpw[sizeof(cpw)-1] = '\0';
      data_data.dptr = cpw;
#endif
    } else
      data_data.dptr = value;    
    
#ifdef DEBUG
    traceEvent(TRACE_INFO, "'%s' <-> '%s'\n", key, data_data.dptr);
#endif
    
    data_data.dsize = strlen(data_data.dptr)+1;
    gdbm_store(pwFile, key_data, data_data, GDBM_REPLACE);
  } else
    free(return_data.dptr);
}

/* *******************************/

void addDefaultAdminUser(void) {
  /* Add user 'admin/admin' if not existing */
  addKeyIfMissing("1admin", "admin", 1);

  /* Add user 'admin' for URL 'show...' if not existing */
  addKeyIfMissing("2showU",    "users=1admin", 0);
  addKeyIfMissing("2modifyU",  "users=1admin", 0);
  addKeyIfMissing("2deleteU",  "users=1admin", 0);
  addKeyIfMissing("2shutdown", "users=1admin", 0);
}

