/*
 *  Copyright (C) 1998-2000 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
 *                      
 *			  Centro SERRA, University of Pisa
 *			  http://www.ntop.org/
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

/* *******************************/

#ifdef HAVE_GDBM_H
void showUsers(void) {
  u_int numUsers=0;
  char buf[BUF_SIZE];
  datum key_data, return_data;

  sendString("<html>\n");
  sendString("<title>Welcome to ntop!</title>\n");
  sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
  sendString("<H1><CENTER>Registered ntop Users</CENTER></H1><p><hr><p>\n");

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "showUsers");
#endif 
  return_data = gdbm_firstkey (pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(TRACE_INFO, "1) -> %s\n", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '1') /* 1 = user */{

      if(numUsers == 0) {
	sendString("<CENTER>"TABLE_ON"<TABLE BORDER=0>\n");
	sendString("<TR><TH "TH_BG">Users</TH><TH "TH_BG">Actions</TH></TR>\n");
      }
	
      if(strcmp(key_data.dptr, "1admin") == 0)
	snprintf(buf, BUF_SIZE, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
		"&nbsp;%s</TH><TD "TD_BG"><A HREF=/modifyUser?%s>"
		"<IMG SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		"&nbsp;</TD></TR></TH></TR>\n", &key_data.dptr[1], key_data.dptr);
      else      
	snprintf(buf, BUF_SIZE, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
		"&nbsp;%s</TH><TD "TD_BG"><A HREF=/modifyUser?%s>"
		"<IMG SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		"&nbsp;<A HREF=/deleteUser?%s><IMG SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
		"</A></TD></TR></TH></TR>\n", &key_data.dptr[1], key_data.dptr, 
		key_data.dptr);
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
    sendString("</TABLE>"TABLE_OFF"\n");
  }

  sendString("<p><H4></center>[<A HREF=addUser.html>Add User</A>]&nbsp;"
	     "[<A HREF=showURLs.html>Show URLs</A>]</H4>\n");
}

/* *******************************/

void addUser(char* user) {
  sendString("<html>\n");
  sendString("<title>Welcome to ntop!</title>\n");
  sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
  sendString("<H1><CENTER>Manage ntop Users</CENTER></H1><p><hr><p>\n");
  sendString("<FORM METHOD=POST ACTION=/doAddUser>\n");
  if(user != NULL) {
    char tmpStr[128];
    
    snprintf(tmpStr, sizeof(tmpStr), "User: <INPUT TYPE=HIDDEN NAME=user SIZE=20 VALUE=\"%s\">"
	     "&nbsp;<b>%s</b>&nbsp;\n", &user[1], &user[1]);
    sendString(tmpStr);
  } else
    sendString("User: <INPUT TYPE=text NAME=user SIZE=20>&nbsp;\n");

  sendString("<br>Password: <INPUT TYPE=password NAME=pw SIZE=20><p>\n");
  if(user != NULL)
    sendString("<input type=submit value=\"Modify User\"><input type=reset></form>\n");
  else
    sendString("<input type=submit value=\"Add User\"><input type=reset></form>\n");
  
  sendString("<p><H4>[<A HREF=showUsers.html>Show Users</A>]&nbsp;"
	     "[<A HREF=showURLs.html>Show URLs</A>]</H4>\n");
}

/* *******************************/

static void redirectURL(char* destination) {
  sendString("HTTP/1.0 302 Found\n");
  sendString("Content-type: text/html\n");
  sendString("Location: /");
  sendString(destination);
  sendString("\n\n");
}

/* *******************************/

void deleteUser(char* user) {
  datum key_data;

  if(user == NULL) {
    redirectURL("showUsers.html");
    return;
  }

  key_data.dptr = user;
  key_data.dsize = strlen(user)+1;
    
#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "redirectURL");
#endif 

  if(gdbm_delete (pwFile, key_data) != 0) {
    sendHTTPProtoHeader(); sendString("Content-type: text/html\n\n");
    sendString("<html>\n");
    sendString("<title>Welcome to ntop!</title>\n");
    sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
    sendString("<H1><CENTER>ntop user delete</CENTER></H1><p><p><hr>\n");
    sendString("FATAL ERROR: unable to delete specified user.");
    sendString("<hr><p><H4>[<A HREF=addUser.html>Add User</A>]"
	       "&nbsp;[<A HREF=showURLs.html>Show URLs</A>]</H4>\n");
    printHTTPtrailer();
  } else {
    redirectURL("showUsers.html");
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
}

/* *******************************/

void doAddUser(int _len) {
  char postData[256], tmpBuf[64], *user=NULL, *pw=NULL, *err=NULL;
  int i, rc, len = _len, idx=0;
  datum data_data, key_data;
#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-newSock);
#endif

  if(_len <= 0) {
    err = "ERROR: both user and password must be non empty fields.";
  } else {

    while(len > 0)
      {
#ifdef HAVE_OPENSSL
	if(newSock < 0) 
	  rc = SSL_read(ssl, &postData[idx], len);
	else
	  rc = recv(newSock, &postData[idx], len, 0);
#else
	rc = recv(newSock, &postData[idx], len, 0);
#endif
	if(rc < 0) {
	  return;
	}

	idx += rc;
	len -= rc;
      }

    postData[idx] = '\0';
    
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

#ifdef DEBUG
    traceEvent(TRACE_INFO, "Data: '%s' (%d)\n", postData, idx); 
#endif

    for(i=0; i<idx; i++) {
      if(postData[i] == '=') {
	if(user == NULL)
	  user = &postData[i+1];
	else
	  pw = &postData[i+1];      
      } else if(postData[i] == '&')
	postData[i] = '\0';
    }

    /* traceEvent(TRACE_INFO, "User='%s' - Pw='%s'\n", user, pw); */

    if((user[0] == '\0') || (pw[0] == '\0'))
      err = "ERROR: both user and password must be non empty fields.";
    else {
      snprintf(tmpBuf, sizeof(tmpBuf), "1%s", user);
      key_data.dptr = tmpBuf;
      key_data.dsize = strlen(tmpBuf)+1;
#ifdef WIN32
      data_data.dptr = pw;
#else
      data_data.dptr = (char*)crypt(pw, (const char*)CRYPT_SALT);
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

#ifdef MULTITHREADED
    releaseMutex(&gdbmMutex);
#endif 
  }

  if(err != NULL) {
    sendHTTPProtoHeader(); sendString("Content-type: text/html\n\n");
    sendString("<html>\n");
    sendString("<title>Welcome to ntop!</title>\n");
    sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
    sendString("<H1><CENTER>ntop user add</CENTER></H1><p><p><hr>\n");
    sendString(err);
    sendString("<hr><p><H4>[<A HREF=addUser.html>Add User</A>]&nbsp;"
	       "[<A HREF=showURLs.html>Show URLs</A>]</H4>\n");
    printHTTPtrailer();
  } else {
    redirectURL("showUsers.html");
  }
}

/* ***********************************
   *********************************** */

void showURLs(void) {
  u_int numUsers=0;
  char buf[BUF_SIZE];
  datum key_data, return_data;

  sendString("<html>\n");
  sendString("<title>Welcome to ntop!</title>\n");
  sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
  sendString("<H1><CENTER>Restricted ntop URLs</CENTER></H1><p><hr><p>\n");

#ifdef MULTITHREADED
    accessMutex(&gdbmMutex, "showURLs");
#endif 
  return_data = gdbm_firstkey (pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(TRACE_INFO, "1) -> %s\n", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '2') { /* 2 = URL */
      if(numUsers == 0) {
	sendString("<CENTER>"TABLE_ON"<TABLE BORDER=0>\n");
	sendString("<TR><TH "TH_BG">URLs</TH><TH "TH_BG">Actions</TH></TR>\n");
      }
	
      snprintf(buf, BUF_SIZE, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
	      "&nbsp;'%s*'</TH><TD "TD_BG"><A HREF=/modifyURL?%s>"
	      "<IMG SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
	      "&nbsp;<A HREF=/deleteURL?%s><IMG SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
	      "</A></TD></TR></TH></TR>\n", &key_data.dptr[1], key_data.dptr, 
	      key_data.dptr);
      sendString(buf);
      numUsers++;      
    }

    return_data = gdbm_nextkey(pwFile, key_data);
    free(key_data.dptr);
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
    
  if(numUsers > 0)
    sendString("</TABLE>"TABLE_OFF"\n");
  
  sendString("<p><H4></center>[<A HREF=addURL.html>Add URL</A>]"
	     "&nbsp;[<A HREF=showUsers.html>Show Users</A>]</H4>\n");  
}

/* *******************************/

void addURL(char* url) {
  datum key_data, return_data;
  char authorisedUsers[BUF_SIZE];

  sendString("<html>\n");
  sendString("<title>Welcome to ntop!</title>\n");
  sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
  sendString("<H1><CENTER>Manage ntop URLs</CENTER></H1><p><hr><p>\n");
  sendString("<FORM METHOD=POST ACTION=/doAddURL>\n");

  if(url != NULL) {
    char tmpStr[128];
    
    snprintf(tmpStr, sizeof(tmpStr), "URL: http://&lt;ntop host&gt;:&lt;ntop port&gt;/"
	    "<INPUT TYPE=HIDDEN NAME=url SIZE=20 VALUE=\"%s\">"
	    "&nbsp;<b>%s</b>&nbsp;<b>*</b> [Initial URL string]\n", &url[1], &url[1]);
    sendString(tmpStr);

    key_data.dptr = url;
    key_data.dsize = strlen(url)+1;
    return_data = gdbm_fetch(pwFile, key_data);

    if(return_data.dptr != NULL)
      strncpy(authorisedUsers, return_data.dptr, BUF_SIZE);
    else
      authorisedUsers[0] = '\0';
  } else  {
    sendString("URL: http://&lt;ntop host&gt;:&lt;ntop port&gt;/"
	       "<INPUT TYPE=text NAME=url SIZE=20>&nbsp;* [Initial URL string]\n");
    sendString("<br><b>Note: if you leave the above field empty then the access is restricted"
	       "to <i>all</i> ntop pages!</b>\n");
  }

#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "addURL");
#endif 
  
  sendString("<br>Authorised Users: <SELECT NAME=users MULTIPLE>\n");

  return_data = gdbm_firstkey(pwFile);

  while (return_data.dptr != NULL) {
    key_data = return_data;

    if(key_data.dptr[0] == '1') { /* 1 = user */
      char tmpStr[128], *selected;

      snprintf(tmpStr, sizeof(tmpStr), "users=%s", key_data.dptr);

      if(strstr(authorisedUsers, tmpStr) != NULL)
	selected = "SELECTED";
      else
	selected = "";

      snprintf(tmpStr, sizeof(tmpStr), "<OPTION VALUE=%s %s>%s", 
	      key_data.dptr, selected, &key_data.dptr[1]);
      sendString(tmpStr);
    }

    return_data = gdbm_nextkey(pwFile, key_data);
    free(key_data.dptr);
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 

  sendString("</SELECT><p>\n");

  if(url != NULL)
    sendString("<input type=submit value=\"Modify URL\"><input type=reset></form>\n");
  else
    sendString("<input type=submit value=\"Add URL\"><input type=reset></form>\n");
  
  sendString("<p><H4>[<A HREF=showUsers.html>Show Users</A>]&nbsp;"
	     "[<A HREF=showURLs.html>Show URLs</A>]</H4>\n");
}

/* *******************************/

void deleteURL(char* user) {
  datum key_data;

  key_data.dptr = user;
  key_data.dsize = strlen(user)+1;
    
#ifdef MULTITHREADED
  accessMutex(&gdbmMutex, "deleteURL");
#endif 

  if(gdbm_delete (pwFile, key_data) != 0) {
    sendHTTPProtoHeader(); sendString("Content-type: text/html\n\n");
    sendString("<html>\n");
    sendString("<title>Welcome to ntop!</title>\n");
    sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
    sendString("<H1><CENTER>ntop URL delete</CENTER></H1><p><p><hr>\n");
    sendString("FATAL ERROR: unable to delete specified URL.");
    sendString("<hr><p><H4>[<A HREF=addURL.html>Add URL</A>]"
	       "&nbsp;[<A HREF=showUsers.html>Show Users</A>]</H4>\n");
    printHTTPtrailer();
  } else {
    redirectURL("showURLs.html");
  }

#ifdef MULTITHREADED
  releaseMutex(&gdbmMutex);
#endif 
}

/* *******************************/

void doAddURL(int _len) {
  char postData[256], tmpBuf[64], *err=NULL;
  int rc, len = _len, idx=0;
  datum data_data, key_data;
#ifdef HAVE_OPENSSL
  SSL* ssl = getSSLsocket(-newSock);
#endif

  if(_len <= 0) {
    err = "ERROR: both url and users must be non empty fields.";
  } else {
    char *url, *users, *strtokState;

    while(len > 0)
      {
#ifdef HAVE_OPENSSL
	if(newSock < 0) 
	  rc = SSL_read(ssl, &postData[idx], len);
	else
	  rc = recv(newSock, &postData[idx], (size_t)len, 0);
#else
	rc = recv(newSock, &postData[idx], (size_t)len, 0);
#endif
	if(rc < 0) {
	  return;
	}

	idx += rc;
	len -= rc;
      }

    postData[idx] = '\0';

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

    /* traceEvent(TRACE_INFO, "Data: '%s' (%d)\n", postData, idx); */

    url = strtok_r(postData, "&", &strtokState);
    url = &url[4 /* strlen("url=") */];

    users = &url[strlen(url)+1];
    
    /* traceEvent(TRACE_INFO, "URL: '%s' - users: '%s'\n", url, users); */

    if(/* (url[0] == '\0') || */ (users[0] == '\0'))
      err = "ERROR: both url and users must be non empty fields.";
    else {
      snprintf(tmpBuf, sizeof(tmpBuf), "2%s", url);
      key_data.dptr = tmpBuf;
      key_data.dsize = strlen(tmpBuf)+1;
      data_data.dptr = users;
      data_data.dsize = strlen(users)+1;
    
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
  }

  if(err != NULL) {
    sendHTTPProtoHeader(); sendString("Content-type: text/html\n\n");
    sendString("<html>\n");
    sendString("<title>Welcome to ntop!</title>\n");
    sendString("</head><BODY BACKGROUND=/white_bg.gif><FONT FACE=Helvetica>\n");
    sendString("<H1><CENTER>ntop URL add</CENTER></H1><p><p><hr>\n");
    sendString(err);
    sendString("<hr><p><H4>[<A HREF=addURL.html>Add URL</A>]"
	       "&nbsp;[<A HREF=showUsers.html>Show Users</A>]</H4>\n");
    printHTTPtrailer();
  } else {
    redirectURL("showURLs.html");
  }
}

/* *******************************/

static void addKeyIfMissing(char* key, char* value, int encryptValue) {
  datum key_data, return_data, data_data;

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
      data_data.dptr = (char*)crypt(value, (const char*)CRYPT_SALT);
#endif
	  } else
      data_data.dptr = value;    

#ifdef DEBUG
    traceEvent(TRACE_INFO, "'%s' <-> '%s'\n", key, data_data.dptr);
#endif

    data_data.dsize = strlen(data_data.dptr)+1;
    gdbm_store(pwFile, key_data, data_data, GDBM_REPLACE);
  }
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


#endif /* HAVE_GDBM_H */
