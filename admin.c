/*
 *  Copyright (C) 1998-2002 Luca Deri <deri@ntop.org>
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


#ifndef MAKE_MICRO_NTOP

/* Forward */
static void sendMenuFooter(int itm1Idx, int itm2Idx);
static void encodeWebFormURL(char *in, char *buf, int buflen);
static void decodeWebFormURL(char *buf);
static int readHTTPpostData(int len, char *buf, int buflen);

/* *******************************/

void showUsers(void) {
  u_int numUsers=0;
  char buf[LEN_GENERAL_WORK_BUFFER], ebuf[128];
  datum key_data, return_data;

  printHTMLheader("Registered ntop Users", BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "showUsers");
#endif
  return_data = gdbm_firstkey(myGlobals.pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(CONST_TRACE_INFO, "1) -> %s\n", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '1') /* 1 = user */{
      if(numUsers == 0) {
	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1>\n");
	sendString("<TR><TH "TH_BG">Users</TH><TH "TH_BG">Actions</TH></TR>\n");
      }

      if(strcmp(key_data.dptr, "1admin") == 0) {
	if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
		    "&nbsp;%s</TH><TD "TD_BG"><A HREF=/modifyUser?%s>"
		    "<IMG ALT=\"Modify User\" SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		    "&nbsp;</TD></TR></TH></TR>\n", &key_data.dptr[1], key_data.dptr) < 0)
	 BufferTooShort();
      } else{
	encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));
	if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
		    "&nbsp;%s</TH><TD "TD_BG"><A HREF=/modifyUser?%s>"
		"<IMG ALT=\"Modify User\" SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		"&nbsp;<A HREF=/deleteUser?%s><IMG ALT=\"Delete User\" SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
		"</A></TD></TR></TH></TR>\n", &key_data.dptr[1], ebuf, ebuf) < 0)
	 BufferTooShort();
      }
      sendString(buf);
      numUsers++;
    }

    return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
    free(key_data.dptr);
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
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

  printHTMLheader("Manage ntop Users", BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

  if((user != NULL) && ((strlen(user) < 2) || (user[0] != '1'))) {
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    sendString("<CENTER>\n");
    
    sendString("<script Language=\"JavaScript\">\nfunction CheckForm(theForm) {\nif (theForm.pw.value != theForm.pw1.value) {\n    alert(\"Passwords do not match. Please try again.\");\n    theForm.pw1.focus();\n    return(false);\n  }\n  return (true);\n}\n</script>\n");
    
    sendString("<FORM METHOD=POST ACTION=/doAddUser onsubmit=\"return CheckForm(this)\">\n");
    
    sendString("<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=5>\n");
    sendString("<TR>\n<TH ALIGN=right>User:&nbsp;</TH><TD ALIGN=left>");
    if(user != NULL) {
      decodeWebFormURL(user);
      if(snprintf(tmpStr, sizeof(tmpStr),
		  "<INPUT TYPE=hidden NAME=user SIZE=20 VALUE=\"%s\"><B>%s</B>\n",
		  &user[1], &user[1]) < 0)
	BufferTooShort();
      sendString(tmpStr);
    } else
      sendString("<INPUT TYPE=text NAME=user SIZE=20>\n");

    sendString("</TD>\n</TR>\n");
    sendString("<TR>\n<TH ALIGN=right>Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw SIZE=20></TD></TR>\n");
    sendString("<TR>\n<TH ALIGN=right>Verify Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw1 SIZE=20></TD></TR>\n");
    sendString("</TABLE>"TABLE_OFF"\n");

    if(snprintf(tmpStr, sizeof(tmpStr),
		"<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset>\n",
		(user != NULL) ? "Modify User" : "Add User") < 0)
      BufferTooShort();
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
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
    printHTMLheader("Delete ntop User", BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    int rc;
    datum key_data;

    decodeWebFormURL(user);
    key_data.dptr = user;
    key_data.dsize = strlen(user)+1;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "deleteUser");
#endif
    rc = gdbm_delete(myGlobals.pwFile, key_data);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    if(rc != 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
      printHTMLheader("Delete ntop User", BITFLAG_HTML_NO_REFRESH);
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
      char tmpBuf[64];
#ifndef WIN32
      char cpw[14];
#endif
      datum data_data, key_data;

      if(snprintf(tmpBuf, sizeof(tmpBuf), "1%s", user) < 0)
	 BufferTooShort();
      key_data.dptr = tmpBuf;
      key_data.dsize = strlen(tmpBuf)+1;
#ifdef WIN32
      data_data.dptr = pw;
#else
      strncpy(cpw, (char*)crypt(pw, (const char*)CONST_CRYPT_SALT), sizeof(cpw));
      cpw[sizeof(cpw)-1] = '\0';
      data_data.dptr = cpw;
#endif
      data_data.dsize = strlen(data_data.dptr)+1;
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "User='%s' - Pw='%s [%s]'\n", user, pw, data_data.dptr);
#endif

#ifdef CFG_MULTITHREADED
      accessMutex(&myGlobals.gdbmMutex, "doAddUser");
#endif
      if(gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE) != 0)
	err = "FATAL ERROR: unable to add the new user.";

#ifdef CFG_MULTITHREADED
      releaseMutex(&myGlobals.gdbmMutex);
#endif
    }
  }

  if(err != NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
    printHTMLheader("ntop user add", BITFLAG_HTML_NO_REFRESH);
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
  char buf[LEN_GENERAL_WORK_BUFFER], ebuf[128];
  datum key_data, return_data;

  printHTMLheader("Restricted ntop URLs", BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.gdbmMutex, "showURLs");
#endif

  return_data = gdbm_firstkey(myGlobals.pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(CONST_TRACE_INFO, "1) -> %s\n", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '2') { /* 2 = URL */
      if(numUsers == 0) {
	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1 CELLSPACING=0 CELLPADDING=5>\n");
	sendString("<TR><TH "TH_BG">URLs</TH><TH "TH_BG">Actions</TH></TR>\n");
      }

      encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));
      if(snprintf(buf, LEN_GENERAL_WORK_BUFFER, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
	      "&nbsp;'%s*'</TH><TD "TD_BG"><A HREF=/modifyURL?%s>"
	      "<IMG ALT=\"Modify User\" SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
	      "&nbsp;<A HREF=/deleteURL?%s><IMG ALT=\"Delete User\" SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
	      "</A></TD></TR></TH></TR>\n", &key_data.dptr[1], ebuf, ebuf) < 0)
	 BufferTooShort();
      sendString(buf);
      numUsers++;
    }

    return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
    free(key_data.dptr);
  }

#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
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

  printHTMLheader("Manage ntop URLs", BITFLAG_HTML_NO_REFRESH);
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
	 BufferTooShort();
      sendString(tmpStr);
    } else {
      sendString("<INPUT TYPE=text NAME=url SIZE=20>&nbsp;*");
    }
    sendString("</TD>\n</TR>\n");
    sendString("<TR>\n<TH ALIGN=right VALIGN=top>Authorised Users:&nbsp;</TH>"
	       "<TD ALIGN=left><SELECT NAME=users MULTIPLE>\n");

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "addURL");
#endif

    authorisedUser[0] = NULL;
    if(url != NULL) {
      key_data.dptr = url;
      key_data.dsize = strlen(url)+1;
      return_data = gdbm_fetch(myGlobals.pwFile, key_data);

      if(return_data.dptr != NULL) {
	char *strtokState, *item;

	aubuf = return_data.dptr; /* freed later (**) */
	item = strtok_r(aubuf, "&", &strtokState);
	for(i=0; (item != NULL) && (i < sizeof(authorisedUser)-1); i++) {
	  authorisedUser[i] = &item[sizeof("users=")-1];
	  item = strtok_r(NULL, "&", &strtokState);
	}
	if(item != NULL) {
	  traceEvent(CONST_TRACE_ERROR, "Too many users for URL='%s'\n", url);
	}
	authorisedUser[i] = NULL;
      }
    }

    return_data = gdbm_firstkey(myGlobals.pwFile);

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
	 BufferTooShort();
        sendString(tmpStr);
      }

      return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
      free(key_data.dptr);
    }

    if(aubuf != NULL)
      free(aubuf); /* (**) */

#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    sendString("</SELECT>\n</TD></TR>\n");
    sendString("</TABLE>"TABLE_OFF"\n");

    if(url == NULL)
      sendString("<BLOCKQUOTE>\n<DIV ALIGN=left>\n"
		 "<B><U>NOTE</U>: if you leave the URL field empty then the "
		 "access is restricted to <I>all</I> ntop pages, otherwise, this "
		 "entry matches all the pages begining with the specified string.</B>\n"
		 "</DIV>\n</BLOCKQUOTE>\n");

    if(snprintf(tmpStr, sizeof(tmpStr),
	     "<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset>\n",
	     (url != NULL) ? "Modify URL" : "Add URL") < 0)
	 BufferTooShort();
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
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
    printHTMLheader("Delete ntop URL", BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning("<I>The specified URL is invalid.</I>");
  } else {
    int rc;
    datum key_data;

    decodeWebFormURL(url);
    key_data.dptr = url;
    key_data.dsize = strlen(url)+1;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "deleteURL");
#endif
    rc = gdbm_delete(myGlobals.pwFile, key_data);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    if(rc != 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
      printHTMLheader("Delete ntop URL", BITFLAG_HTML_NO_REFRESH);
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
	 BufferTooShort();
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
     BufferTooShort();
    key_data.dptr = tmpBuf;
    key_data.dsize = strlen(tmpBuf)+1;
    data_data.dptr = authorizedUsers;
    data_data.dsize = strlen(authorizedUsers)+1;

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "doAddURL");
#endif
    if(gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE) != 0)
      err = "FATAL ERROR: unable to add the new URL.";
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif
  }
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
#endif

  if(err != NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);
    printHTMLheader("ntop URL add", BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning(err);
    sendMenuFooter(3, 0);
    printHTMLtrailer();
  } else {
    returnHTTPredirect("showURLs.html");
  }
}

/* *******************************/

/* Courtesy of Michael Weidel <michael.weidel@gmx.de> */

int doChangeFilter(int len) {
  int i,idx,badChar=0;
  struct bpf_program fcode;
  char *currentFilterExpressionSav;
  char buf[LEN_GENERAL_WORK_BUFFER],postData[256],*key,*err=NULL;

  currentFilterExpressionSav = strdup(myGlobals.currentFilterExpression);  /* Backup */

  if((idx = readHTTPpostData(len, postData, sizeof(postData))) < 0)
    return 1;

  for(i=0,key=postData; i<=idx; i++) {
    if(postData[i] == '&') {
      postData[i] = '\0';
      key = &postData[i+1];
    } else if((key != NULL) && (postData[i] == '=')) {
      postData[i] = '\0';
      if(strcmp(key, "filter") == 0) {
	myGlobals.currentFilterExpression = strdup(&postData[i+1]);
      }
      key = NULL;
    }
  }
  if(key == NULL) {
    decodeWebFormURL(myGlobals.currentFilterExpression);
    for(i=0; i<strlen(myGlobals.currentFilterExpression); i++) {
      if(!(isalpha(myGlobals.currentFilterExpression[i]) ||
	   isdigit(myGlobals.currentFilterExpression[i]) ||
	  (strchr("/-+*_.!&|><=\\\":[]() ", myGlobals.currentFilterExpression[i]) != NULL))) {
       badChar = 1;	       /* Perhaps we don't have to use this check? */
       break;
      }
    }
  } else err = "ERROR: The HTTP Post Data was invalid.";
  if(badChar)
    err = "ERROR: the specified filter expression contains invalid characters.";
  if(err==NULL) {
    traceEvent(CONST_TRACE_INFO, "Changing the kernel (libpcap) filter...");

#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "changeFilter");
#endif

    for(i=0; i<myGlobals.numDevices; i++) {
      if((!myGlobals.device[i].virtualDevice)&&(err==NULL)) {
	if((pcap_compile(myGlobals.device[i].pcapPtr, &fcode, myGlobals.currentFilterExpression, 1,
			myGlobals.device[i].netmask.s_addr) < 0)
	   || (pcap_setfilter(myGlobals.device[i].pcapPtr, &fcode) < 0)) {
	  traceEvent(CONST_TRACE_ERROR,
		    "ERROR: wrong filter '%s' (%s) on interface %s.\nUsing old filter.\n",
		    myGlobals.currentFilterExpression, pcap_geterr(myGlobals.device[i].pcapPtr), myGlobals.device[i].name);
	  err="The syntax of the defined filter is wrong.";
	} else{
	 if(*myGlobals.currentFilterExpression!='\0'){
	   traceEvent(CONST_TRACE_INFO, "Set filter \"%s\" on myGlobals.device %s.",
		      myGlobals.currentFilterExpression, myGlobals.device[i].name);
	 }else{
	   traceEvent(CONST_TRACE_INFO, "Set no kernel (libpcap) filtering on myGlobals.device %s.",
		      myGlobals.device[i].name);
	 }
	}
      }
    }

#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif
  }
  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0);

  if(myGlobals.filterExpressionInExtraFrame) {
    sendString("<HTML>\n<HEAD>\n");
    sendString("<LINK REL=stylesheet HREF=/style.css type=\"text/css\">\n");
    sendString("<SCRIPT TYPE=\"text/javascript\">\n");
    sendString("<!--\nfunction UpdateFrame(URI,F) {\n");
    sendString("  Frame=eval(\"parent.\"+F);\n");
    sendString("  Frame.location.href = URI;\n");
    sendString("}\n//-->\n</SCRIPT>");
    sendString("</HEAD>\n");
    sendString("<BODY ONLOAD=\"UpdateFrame('"FILTER_INFO_HTML"','filterinfo')\" ");
    sendString("BACKGROUND=/white_bg.gif BGCOLOR=\"#FFFFFF\" LINK=blue VLINK=blue>\n");
    printSectionTitle("Change kernel (libpcap) filter expression");
  } else {
    printHTMLheader("changing kernel (libpcap) filter expression", BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR></P>\n<P><CENTER>");
  }

  sendString("<FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");

  if(err == NULL) {
    if(*myGlobals.currentFilterExpression != '\0'){
      if(snprintf(buf, sizeof(buf),
		  "<B>Filter changed to <I>%s</I>.</B></FONT>\n",
		 myGlobals.currentFilterExpression) < 0)
      BufferTooShort();
      sendString(buf);
    } else sendString("<B>Kernel (libpcap) filtering disabled.</B></FONT>\n");

    if(myGlobals.filterExpressionInExtraFrame) {
      sendString("<NOSCRIPT>\n<P>You've got JavaScript disabled. Therefore ");
      sendString("your extra frame with the filter expression isn't updated ");
      sendString("automatically. No problem, you can update it here ");
      sendString("<A HREF=\""FILTER_INFO_HTML"\" target=\"filterinfo\">");
      sendString("manually</A>.</NOSCRIPT></P>");
      sendString("</BODY>\n</HTML>\n");
    } else {
      sendString("</CENTER></P>\n");
      /* sendString("<P><CENTER>The statistics are also reset.</CENTER></P>\n"); */
      printHTMLtrailer();
    }

    if(currentFilterExpressionSav != NULL) free(currentFilterExpressionSav);
    return 0; /* -> Statistics are reset (if uncommented) */
  } else {
    if(myGlobals.currentFilterExpression!=NULL) free(myGlobals.currentFilterExpression);
    myGlobals.currentFilterExpression = currentFilterExpressionSav;
    for(i=0; i<myGlobals.numDevices; i++) {      /* restore old filter expression */
      if((!myGlobals.device[i].virtualDevice)&&(err==NULL)) {
	if((pcap_compile(myGlobals.device[i].pcapPtr, &fcode, myGlobals.currentFilterExpression, 1,
			myGlobals.device[i].netmask.s_addr) < 0)
	   || (pcap_setfilter(myGlobals.device[i].pcapPtr, &fcode) < 0)) {
	  traceEvent(CONST_TRACE_ERROR,
		    "ERROR: wrong filter '%s' (%s) on interface %s.\nUsing old filter.\n",
		    myGlobals.currentFilterExpression, pcap_geterr(myGlobals.device[i].pcapPtr), myGlobals.device[i].name);
	}
      }
    }

    printFlagedWarning(err);
    if(myGlobals.filterExpressionInExtraFrame) sendString("</BODY>\n</HTML>\n");
    else printHTMLtrailer();
    return 2;
  }
}

/* ******************************* */

/* Courtesy of Michael Weidel <michael.weidel@gmx.de> */

void changeFilter(void) {
  char buf[LEN_GENERAL_WORK_BUFFER];

  printHTMLheader("Change kernel (libpcap) filter expression", BITFLAG_HTML_NO_REFRESH);
  sendString("<BR><HR><P>\n");
  sendString("<TABLE BORDER=0 CELLSPACING=0 CELLPADDING=5>\n<TR>\n");
  sendString("<TH "TH_BG" ALIGN=center>Old Filter Expression:&nbsp;</TH><TD ALIGN=left>");
  if(snprintf(buf, sizeof(buf), "<B>%s",
	     myGlobals.currentFilterExpression) < 0)
   BufferTooShort();
  sendString(buf);
  if(*myGlobals.currentFilterExpression == '\0') sendString("&lt;No filter defined&gt;");
  sendString("</B><BR>\n</TD>\n</TR>\n");

  sendString("<FORM METHOD=POST ACTION=/doChangeFilter>\n");
  sendString("<TR>\n<TH "TH_BG" ALIGN=center>New Filter Expression:&nbsp;</TH>");
  sendString("<TD ALIGN=left><INPUT TYPE=text NAME=filter SIZE=40>\n");
  sendString("</TD>\n</TR>\n</TABLE>"TABLE_OFF"\n<CENTER>");
  sendString("<INPUT TYPE=submit VALUE=\"Change Filter\">&nbsp;&nbsp;&nbsp;");
  sendString("<INPUT TYPE=reset></FORM>");

  sendString("</CENTER></P><P></B>\n<FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");
  sendString("You can use all filter expressions libpcap can handle, \n");
  sendString("like the ones you pass to tcpdump.<BR>\n");
  sendString("If \"new filter expression\" is left empty, no filtering is performed.<BR>\n");
  sendString("If you want the statistics to be reset, you have to do that manually ");
  sendString("with <A HREF=\"resetStats.html\">Reset Stats</A>.<BR>\n");
  sendString("<B>Be careful</B>: That can take quite a long time!");
  sendString("<BR><B></FONT>\n");
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
	 BufferTooShort();
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
    } else if(c == ' ') {
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
  SSL* ssl = getSSLsocket(-myGlobals.newSock);
#endif

  memset(buf, 0, buflen);

  if(len > (buflen-8)) {
    traceEvent(CONST_TRACE_ERROR, "Too much HTTP POST data");
    return (-1);
  }

  while(len > 0) {
#ifdef HAVE_OPENSSL
    if(myGlobals.newSock < 0)
      rc = SSL_read(ssl, &buf[idx], len);
    else
      rc = recv(myGlobals.newSock, &buf[idx], len, 0);
#else
    rc = recv(myGlobals.newSock, &buf[idx], len, 0);
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
    FD_SET((unsigned int)abs(myGlobals.newSock), &mask);

    /* select returns immediately */
    wait_time.tv_sec = 0, wait_time.tv_usec = 0;
    if(select(myGlobals.newSock+1, &mask, 0, 0, &wait_time) == 1) {
      char aChar[8]; /* just in case */

#ifdef HAVE_OPENSSL
      if(myGlobals.newSock < 0)
	rc = SSL_read(ssl, aChar, 1);
      else
	rc = recv(myGlobals.newSock, aChar, 1, 0);
#else
      rc = recv(myGlobals.newSock, aChar, 1, 0);
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
  traceEvent(CONST_TRACE_INFO, "Data: '%s' (%d)\n", buf, idx);
#endif

  return (idx);
}
#endif /* MAKE_MICRO_NTOP */


/* ****************************** */

/*
  Fixes below courtesy of
  C C Magnus Gustavsson <magnus@gustavsson.se>
*/
static void addKeyIfMissing(char* key, char* value, 
			    int encryptValue, int existingOK,
			    char *userQuestion) {
  datum key_data, return_data, data_data;
#ifndef WIN32
  char cpw[14];
#endif

  /* Check existence of user 'admin' */
  key_data.dptr = key;
  key_data.dsize = strlen(key_data.dptr)+1;

#ifdef CFG_MULTITHREADED
  accessMutex(&myGlobals.gdbmMutex, "addKey");
#endif
  return_data = gdbm_fetch(myGlobals.pwFile, key_data);
#ifdef CFG_MULTITHREADED
  releaseMutex(&myGlobals.gdbmMutex);
#endif

  if((return_data.dptr == NULL) || (existingOK != 0)) {
    char *thePw, pw1[16], pw2[16];
    /* If not existing, then add user 'admin' and ask for password  */

    if(userQuestion != NULL) {
      if (myGlobals.daemonMode) {
	/*
	 * We need a password for the admin user, but the user requested
	 * daemon mode.  stdin is already detached; getpass() would fail.
	 *
	 * Courtesy of Ambrose Li <a.c.li@ieee.org>
	 *
	 */
	traceEvent(CONST_TRACE_ERROR, "No password for admin user. Please re-run ntop in non-daemon mode first.\n");
	exit(1);
      }

      memset(pw1, 0, sizeof(pw1)); memset(pw2, 0, sizeof(pw2));

      while(pw1[0] == '\0') {
        thePw = getpass(userQuestion);
#ifdef WIN32
        if ( (isWinNT()) || (strlen(thePw) >= 5) ) {
#else
        if (strlen(thePw) >= 5) {
#endif
          if(strlen(thePw) > (sizeof(pw1)-1)) thePw[sizeof(pw1)-1] = '\0';
          strcpy(pw1, thePw);

          thePw = getpass("Please enter the password again: ");

          if(strlen(thePw) > (sizeof(pw2)-1)) thePw[sizeof(pw2)-1] = '\0';
            strcpy(pw2, thePw);

          if(strcmp(pw1, pw2)) {
            printf("Passwords don't match. Please try again.\n");
            memset(pw1, 0, sizeof(pw1)); memset(pw2, 0, sizeof(pw2));
            sleep(1); /* It avoids message loops */
          }
        } else {
	  printf("Password too short (5 characters or more). Please try again.\n");
	}
      }

      value = pw1;
    }

    if(encryptValue) {
#ifdef WIN32
      data_data.dptr = value;
#else
      strncpy(cpw, (char*)crypt(value, (const char*)CONST_CRYPT_SALT), sizeof(cpw));
      cpw[sizeof(cpw)-1] = '\0';
      data_data.dptr = cpw;
#endif
    } else
      data_data.dptr = value;

#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "'%s' <-> '%s'\n", key, data_data.dptr);
#endif

    data_data.dsize = strlen(data_data.dptr)+1;
#ifdef CFG_MULTITHREADED
    accessMutex(&myGlobals.gdbmMutex, "showUsers");
#endif
    gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE);
#ifdef CFG_MULTITHREADED
    releaseMutex(&myGlobals.gdbmMutex);
#endif

    /* print notice to the user */
    if(memcmp(key,"1admin",6) == 0)
      traceEvent(CONST_TRACE_INFO, "Admin user password has been set.\n");

  } else
    free(return_data.dptr);
}

/* *******************************/

void setAdminPassword(char* pass) {
  if (pass == NULL)
    addKeyIfMissing("1admin", NULL, 1, 1, "\nPlease enter the password for the admin user: ");
  else
    addKeyIfMissing("1admin", pass, 1, 1, NULL);
}

/* *******************************/

void addDefaultAdminUser(void) {
  /* Add user 'admin' and ask for password if not existing */
  addKeyIfMissing("1admin", NULL, 1, 0, "\nPlease enter the password for the admin user: ");

  /* Add user 'admin' for URL 'show...' if not existing */
  addKeyIfMissing("2showU",      "users=1admin", 0, 0, NULL);
  addKeyIfMissing("2modifyU",    "users=1admin", 0, 0, NULL);
  addKeyIfMissing("2deleteU",    "users=1admin", 0, 0, NULL);
  addKeyIfMissing("2shut",       "users=1admin", 0, 0, NULL);
  addKeyIfMissing("2resetStats", "users=1admin", 0, 0, NULL);
  addKeyIfMissing("2chang",      "users=1admin", 0, 0, NULL);
}

