/*
 *  Copyright (C) 1998-2004 Luca Deri <deri@ntop.org>
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


/* Forward */
static void sendMenuFooter(int itm1Idx, int itm2Idx);
static void encodeWebFormURL(char *in, char *buf, int buflen);
static void decodeWebFormURL(char *buf);
static void copyUserPrefs (UserPref *from, UserPref *to);
static int processNtopConfigData (char *buf, int savePref);

/* *******************************/

void showUsers(void) {
  u_int numUsers=0;
  char buf[LEN_GENERAL_WORK_BUFFER];
  datum key_data, return_data;

  printHTMLheader("Registered ntop Users", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

  return_data = gdbm_firstkey(myGlobals.pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(CONST_TRACE_INFO, "1) -> %s", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '1') /* 1 = user */{
      if(numUsers == 0) {
	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n");
	sendString("<TR "DARK_BG"><TH "TH_BG">Users</TH><TH "TH_BG">Actions</TH></TR>\n");
      }

      if(strcmp(key_data.dptr, "1admin") == 0) {
	safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
                      "<tr><th "TH_BG" align=\"left\"><img src=\"/user.gif\">"
		      "&nbsp;%s</th><td "TD_BG"><a href=\"/%s?%s\">"
                      "<img alt=\"Modify User\" src=\"/modifyUser.gif\" "
                        "border=\"0\" align=\"absmiddle\"></a>"
                      "&nbsp;</td></tr></th></tr>\n",
                      &key_data.dptr[1], CONST_MODIFY_USERS, key_data.dptr);
      } else{
	char ebuf[256];
	encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));

	safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
                      "<tr><th "TH_BG" align=\"left\"><img src=\"/user.gif\">"
                      "&nbsp;%s</tg><td "TD_BG"><a href=\"/%s?%s\">"
                      "<img alt=\"Modify User\" src=\"/modifyUser.gif\" border=\"0\" "
                          "align=\"absmiddle\"></a>"
                      "&nbsp;<A HREF=/%s?%s>"
                      "<img alt=\"Delete User\" src=\"/deleteUser.gif\" border=\"0\" "
                          "align=\"absmiddle\">"
                      "</a></td></tr></th></tr>\n",
                      &key_data.dptr[1], CONST_MODIFY_USERS, ebuf, CONST_DELETE_USER, ebuf);
      }
      sendString(buf);
      numUsers++;
    }

    return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
    free(key_data.dptr);
  }

  if(numUsers > 0) {
    sendString("</TABLE>"TABLE_OFF"\n<P>\n");
    sendString("</CENTER>\n");
  }
  sendMenuFooter(1, 2);
}

/* *******************************/

void clearUserUrlList(void) {
  int i;

  /*
   * We just changed the database.
   * Delete the in-memory copy so next time we reference it,
   * it will be reloaded with the new values
   */

  traceEvent(CONST_TRACE_NOISY, "SECURITY: Loading items table");

#ifdef CFG_MULTITHREADED
  if(myGlobals.securityItemsMutex.isInitialized == 1)
    accessMutex(&myGlobals.securityItemsMutex, "clear");
#endif

  for (i=0; i<myGlobals.securityItemsLoaded; i++) {
    free(myGlobals.securityItems[i]);
  }
  myGlobals.securityItemsLoaded = 0;

#ifdef CFG_MULTITHREADED
  if(myGlobals.securityItemsMutex.isInitialized == 1)
    releaseMutex(&myGlobals.securityItemsMutex);
#endif
}

/* *******************************/

void addUser(char* user) {
  char tmpStr[128];

  printHTMLheader("Manage ntop Users", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

  if((user != NULL) && ((strlen(user) < 2) || (user[0] != '1'))) {
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    sendString("<CENTER>\n");

    sendString("<script Language=\"JavaScript\">\nfunction CheckForm(theForm) {\nif (theForm.pw.value != theForm.pw1.value) {\n    alert(\"Passwords do not match. Please try again.\");\n    theForm.pw1.focus();\n    return(false);\n  }\n  return (true);\n}\n</script>\n");

    sendString("<FORM METHOD=POST ACTION=/doAddUser onsubmit=\"return CheckForm(this)\">\n");

    sendString("<TABLE BORDER=0 "TABLE_DEFAULTS">\n");
    sendString("<TR>\n<TH ALIGN=right>User:&nbsp;</TH><TD ALIGN=left>");
    if(user != NULL) {
      decodeWebFormURL(user);
      safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		  "<INPUT TYPE=hidden NAME=user SIZE=20 VALUE=\"%s\"><B>%s</B>\n",
		  &user[1], &user[1]);
      sendString(tmpStr);
    } else
      sendString("<INPUT TYPE=text NAME=user SIZE=20>\n");

    sendString("</TD>\n</TR>\n");
    sendString("<TR>\n<TH ALIGN=right>Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw SIZE=20></TD></TR>\n");
    sendString("<TR>\n<TH ALIGN=right>Verify Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw1 SIZE=20></TD></TR>\n");
    sendString("</TABLE>"TABLE_OFF"\n");

    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		"<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset VALUE=Reset>\n",
		(user != NULL) ? "Modify User" : "Add User");
    sendString(tmpStr);

    sendString("</FORM>\n");
    sendString("</CENTER>\n");
  }
  sendMenuFooter(0, 2);
}

/* *******************************/

void deleteUser(char* user) {
  if(user == NULL) {
    returnHTTPredirect(CONST_SHOW_USERS_HTML);
    return;
  } else if((strlen(user) < 2) || (user[0] != '1')) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("Delete ntop User", NULL, BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    int rc;
    datum key_data;

    decodeWebFormURL(user);
    key_data.dptr = user;
    key_data.dsize = strlen(user)+1;

    /* Delete a URL - clear the list */
    clearUserUrlList();

    rc = gdbm_delete(myGlobals.pwFile, key_data);

    if(rc != 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      printHTMLheader("Delete ntop User", NULL, BITFLAG_HTML_NO_REFRESH);
      sendString("<P><HR><P>\n");
      printFlagedWarning("<B>ERROR:</B> <I>unable to delete specified user.</I>");
    } else {
      returnHTTPredirect(CONST_SHOW_USERS_HTML);
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
      /* 14 is ok for traditional crypt, but the enhanced crypt() in FreeBSD
       * (and others?) can be much larger. Just us a big buffer for ALL OSes
       * in case others change too...
       */
      char cpw[LEN_MEDIUM_WORK_BUFFER];
#endif
      datum data_data, key_data;

      safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "1%s", user);
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
      traceEvent(CONST_TRACE_INFO, "User='%s' - Pw='%s [%s]'", user, pw, data_data.dptr);
#endif

      if(gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE) != 0)
	err = "FATAL ERROR: unable to add the new user.";

      /* Added user, clear the list */
      clearUserUrlList();

#ifdef HAVE_CRYPTGETFORMAT
      /* If we have the routine, store the crypt type too */
      {
        char cgf[LEN_MEDIUM_WORK_BUFFER];
        safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "3%s", user);
        key_data.dptr = tmpBuf;
        key_data.dsize = strlen(tmpBuf)+1;
        strncpy(cgf, (char*)crypt_get_format(),  sizeof(cgf));
        cgf[sizeof(cgf)-1] = '\0';
        data_data.dptr = cgf;
        data_data.dsize = strlen(data_data.dptr)+1;
        gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE);
      }
#endif

    }
  }

if(err != NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop user add", NULL, BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning(err);
    sendMenuFooter(1, 2);
    printHTMLtrailer();
  } else {
    returnHTTPredirect(CONST_SHOW_USERS_HTML);
  }
}

/* ***********************************
   *********************************** */

void showURLs(void) {
  u_int numUsers=0;
  char buf[LEN_GENERAL_WORK_BUFFER], ebuf[256];
  datum key_data, return_data;

  printHTMLheader("Restricted ntop URLs", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

  return_data = gdbm_firstkey(myGlobals.pwFile);

  while (return_data.dptr != NULL) {
    /* traceEvent(CONST_TRACE_INFO, "1) -> %s", return_data.dptr); */
    key_data = return_data;

    if(key_data.dptr[0] == '2') { /* 2 = URL */
      if(numUsers == 0) {
	sendString("<CENTER>\n"
		   ""TABLE_ON"<TABLE BORDER=1 "TABLE_DEFAULTS">\n");
	sendString("<TR "DARK_BG"><TH "TH_BG">URLs</TH><TH "TH_BG">Actions</TH></TR>\n");
      }

      encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));
      safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER, "<TR><TH "TH_BG" ALIGN=LEFT><IMG SRC=/user.gif>"
	      "&nbsp;'%s*'</TH><TD "TD_BG"><A HREF=/%s?%s>"
		  "<IMG ALT=\"Modify URL\" SRC=/modifyUser.gif BORDER=0 align=absmiddle></A>"
		  "&nbsp;<A HREF=/%s?%s><IMG ALT=\"Delete URL\" SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
		  "</A></TD></TR></TH></TR>\n", &key_data.dptr[1], CONST_MODIFY_URL, ebuf, CONST_DELETE_URL, ebuf);
      sendString(buf);
      numUsers++;
    }

    return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
    free(key_data.dptr);
  }

  if(numUsers > 0) {
    sendString("</TABLE>"TABLE_OFF"\n<P>\n");
    sendString("</CENTER>\n");
  }
  sendMenuFooter(3, 0);
}

/* *******************************/

void addURL(char* url) {
  int i, numUsers=0;
  datum key_data, return_data;
  char *aubuf=NULL, *authorisedUser[20];
  char tmpStr[128];

  printHTMLheader("Manage ntop URLs", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

  if((url != NULL) && ((strlen(url) < 1) || (url[0] != '2'))) {
    printFlagedWarning("<I>The specified URL is invalid.</I>");

  } else {
    sendString("<CENTER>\n");
    sendString("<FORM METHOD=POST ACTION=/doAddURL>\n");

    sendString("<TABLE BORDER=0 "TABLE_DEFAULTS">\n");
    if(url != NULL)
      sendString("<TR>\n<TH ALIGN=right VALIGN=top><B>URL</B>:&nbsp;</TH>");
    else
      sendString("<TR>\n<TH ALIGN=right VALIGN=middle><B>URL</B>:&nbsp;</TH>");
    sendString("<TD ALIGN=left><TT>http://&lt;"
	       "<I>ntop host</I>&gt;:&lt;<I>ntop port</I>&gt;/</TT>");
    if(url != NULL) {
      decodeWebFormURL(url);
      safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
	       "<INPUT TYPE=hidden NAME=url SIZE=20 VALUE=\"%s\">"
	       "<B>%s</B>&nbsp;<B>*</B>  [Initial URL string]",
	       &url[1], &url[1]);
      sendString(tmpStr);
    } else {
      sendString("<INPUT TYPE=text NAME=url SIZE=20>&nbsp;*");
    }
    sendString("</TD>\n</TR>\n");
    sendString("<TR>\n<TH ALIGN=right VALIGN=top>Authorised Users:&nbsp;</TH>"
	       "<TD ALIGN=left><SELECT NAME=users MULTIPLE>\n");

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
	  traceEvent(CONST_TRACE_ERROR, "Too many users for URL='%s'", url);
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

	/* Make sure that at least a user is selected */
	if((numUsers == 0) && (authorisedUser[0] == NULL)) found = 1;

        safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
		    "<option value=%s %s>%s</option>",
		    key_data.dptr, found ? "SELECTED" : "", &key_data.dptr[1]);
        sendString(tmpStr);
	numUsers++;
      }

      return_data = gdbm_nextkey(myGlobals.pwFile, key_data);
      free(key_data.dptr);
    }

    if(aubuf != NULL)
      free(aubuf); /* (**) */

    sendString("</SELECT>\n</TD></TR>\n");
    sendString("</TABLE>"TABLE_OFF"\n");

    if(url == NULL)
      sendString("<BLOCKQUOTE>\n<DIV ALIGN=left>\n"
		 "<B><U>NOTE</U>: if you leave the URL field empty then the "
		 "access is restricted to <I>all</I> ntop pages, otherwise, this "
		 "entry matches all the pages begining with the specified string.</B>\n"
		 "</DIV>\n</BLOCKQUOTE>\n");

    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
	     "<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset VALUE=Reset>\n",
	     (url != NULL) ? "Modify URL" : "Add URL");
    sendString(tmpStr);

    sendString("</FORM>\n");
    sendString("</CENTER>\n");

  }
  sendMenuFooter(0, 2);
}

/* *******************************/

void deleteURL(char* url) {

  if(url == NULL) {
    returnHTTPredirect(CONST_SHOW_URLS_HTML);
    return;
  } else if((strlen(url) < 1) || (url[0] != '2')) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("Delete ntop URL", NULL, BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning("<I>The specified URL is invalid.</I>");
  } else {
    int rc;
    datum key_data;

    decodeWebFormURL(url);
    key_data.dptr = url;
    key_data.dsize = strlen(url)+1;

    /* Delete URL, clear the list */
    clearUserUrlList();

    rc = gdbm_delete(myGlobals.pwFile, key_data);

    if(rc != 0) {
      sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
      printHTMLheader("Delete ntop URL", NULL, BITFLAG_HTML_NO_REFRESH);
      sendString("<P><HR><P>\n");
      printFlagedWarning("<B>ERROR:</B> <I>unable to delete specified URL.</I>");
    } else {
      returnHTTPredirect(CONST_SHOW_URLS_HTML);
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
	safe_snprintf(__FILE__, __LINE__, &authorizedUsers[alen], sizeof(authorizedUsers)-alen,
		    "%susers=%s", (alen>0) ? "&" : "", users);
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
      if(!(isalpha(url[i]) || isdigit(url[i]) || (strchr("/-_?.", url[i]) != NULL))) {
	badChar = 1;
	break;
      }
    }
  }

#if 0
  printf("URL: '%s' - users: '%s'\n", url ? url : "(not given)", 
	 strlen(authorizedUsers) > 0 ? authorizedUsers : "(not given)");
  fflush(stdout);
#endif

  if(authorizedUsers[0] == '\0') {
    err = "ERROR: user must be a non empty field.";
  } else if(badChar) {
    err = "ERROR: the specified URL contains invalid characters.";
  } else {
    char tmpBuf[64];
    datum data_data, key_data;

    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf), "2%s", url);
    key_data.dptr = tmpBuf;
    key_data.dsize = strlen(tmpBuf)+1;
    data_data.dptr = authorizedUsers;
    data_data.dsize = strlen(authorizedUsers)+1;

    if(gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE) != 0)
      err = "FATAL ERROR: unable to add the new URL.";

    /* Added url, clear the list */
    clearUserUrlList();
  }

  if(err != NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop URL add", NULL, BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR><P>\n");
    printFlagedWarning(err);
    sendMenuFooter(3, 0);
    printHTMLtrailer();
  } else {
    returnHTTPredirect(CONST_SHOW_URLS_HTML);
  }
}

/* *******************************/

/* Courtesy of Michael Weidel <michael.weidel@gmx.de> */

int doChangeFilter(int len) {
  int i,idx,badChar=0;
  struct bpf_program fcode;
  char *currentFilterExpressionSav;
  char buf[LEN_GENERAL_WORK_BUFFER],postData[256],*key,*err=NULL;

  currentFilterExpressionSav = strdup(myGlobals.runningPref.currentFilterExpression);  /* Backup */

  if((idx = readHTTPpostData(len, postData, sizeof(postData))) < 0)
    return 1;

  for(i=0,key=postData; i<=idx; i++) {
    if(postData[i] == '&') {
      postData[i] = '\0';
      key = &postData[i+1];
    } else if((key != NULL) && (postData[i] == '=')) {
      postData[i] = '\0';
      if(strcmp(key, "filter") == 0) {
	myGlobals.runningPref.currentFilterExpression = strdup(&postData[i+1]);
      }
      key = NULL;
    }
  }
  if(key == NULL) {
    decodeWebFormURL(myGlobals.runningPref.currentFilterExpression);
    for(i=0; i<strlen(myGlobals.runningPref.currentFilterExpression); i++) {
      if(!(isalpha(myGlobals.runningPref.currentFilterExpression[i]) ||
	   isdigit(myGlobals.runningPref.currentFilterExpression[i]) ||
	  (strchr("/-+*_.!&|><=\\\":[]() ", myGlobals.runningPref.currentFilterExpression[i]) != NULL))) {
       badChar = 1;	       /* Perhaps we don't have to use this check? */
       break;
      }
    }
  } else err = "ERROR: The HTTP Post Data was invalid.";
  if(badChar)
    err = "ERROR: the specified filter expression contains invalid characters.";
  if(err==NULL) {
    traceEvent(CONST_TRACE_INFO, "Changing the kernel (libpcap) filter...");

    for(i=0; i<myGlobals.numDevices; i++) {
      if(myGlobals.device[i].pcapPtr && (!myGlobals.device[i].virtualDevice) && (err==NULL)) {
	if((pcap_compile(myGlobals.device[i].pcapPtr, &fcode, myGlobals.runningPref.currentFilterExpression, 1,
			myGlobals.device[i].netmask.s_addr) < 0)
	   || (pcap_setfilter(myGlobals.device[i].pcapPtr, &fcode) < 0)) {
	  traceEvent(CONST_TRACE_ERROR,
		    "Wrong filter '%s' (%s) on interface %s - using old filter",
		    myGlobals.runningPref.currentFilterExpression, pcap_geterr(myGlobals.device[i].pcapPtr), myGlobals.device[i].name);
	  err="The syntax of the defined filter is wrong.";
	} else{
#ifdef HAVE_PCAP_FREECODE
         pcap_freecode(&fcode);
#endif
	 if(*myGlobals.runningPref.currentFilterExpression!='\0'){
	   traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Set filter \"%s\" on interface %s",
		      myGlobals.runningPref.currentFilterExpression, myGlobals.device[i].name);
	 }else{
	   traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Set no kernel (libpcap) filtering on interface %s",
		      myGlobals.device[i].name);
	 }
	}
      }
    }
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  if(myGlobals.runningPref.filterExpressionInExtraFrame) {
    sendString((myGlobals.runningPref.w3c == TRUE) ? CONST_W3C_DOCTYPE_LINE "\n" : "");
    sendString("<HTML>\n<HEAD>\n");
    sendString((myGlobals.runningPref.w3c == TRUE) ? CONST_W3C_CHARTYPE_LINE "\n" : "");
    sendString("<LINK REL=stylesheet HREF=\"/style.css\" type=\"text/css\">\n");
    sendString("<SCRIPT TYPE=\"text/javascript\">\n");
    sendString("<!--\nfunction UpdateFrame(URI,F) {\n");
    sendString("  Frame=eval(\"parent.\"+F);\n");
    sendString("  Frame.location.href = URI;\n");
    sendString("}\n//-->\n</SCRIPT>");
    sendString("</HEAD>\n");
    sendString("<BODY ONLOAD=\"UpdateFrame('" CONST_FILTER_INFO_HTML "','filterinfo')\" ");
    sendString("BACKGROUND=/white_bg.gif BGCOLOR=\"#FFFFFF\" LINK=blue VLINK=blue>\n");
    printSectionTitle("Change kernel (libpcap) filter expression");
  } else {
    printHTMLheader("changing kernel (libpcap) filter expression", NULL, BITFLAG_HTML_NO_REFRESH);
    sendString("<P><HR></P>\n<P><CENTER>");
  }

  sendString("<FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");

  if(err == NULL) {
    if(*myGlobals.runningPref.currentFilterExpression != '\0'){
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<B>Filter changed to <I>%s</I>.</B></FONT>\n",
		 myGlobals.runningPref.currentFilterExpression);
      sendString(buf);
    } else sendString("<B>Kernel (libpcap) filtering disabled.</B></FONT>\n");

    if(myGlobals.runningPref.filterExpressionInExtraFrame) {
      sendString("<NOSCRIPT>\n<P>You've got JavaScript disabled. Therefore ");
      sendString("your extra frame with the filter expression isn't updated ");
      sendString("automatically. No problem, you can update it here ");
      sendString("<A HREF=\"" CONST_FILTER_INFO_HTML "\" target=\"filterinfo\">");
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
    if(myGlobals.runningPref.currentFilterExpression != NULL)
        free(myGlobals.runningPref.currentFilterExpression);
    myGlobals.runningPref.currentFilterExpression = currentFilterExpressionSav;
    for(i=0; i<myGlobals.numDevices; i++) {      /* restore old filter expression */
      if(myGlobals.device[i].pcapPtr && (!myGlobals.device[i].virtualDevice) && (err==NULL)) {
	if((pcap_compile(myGlobals.device[i].pcapPtr, &fcode,
                         myGlobals.runningPref.currentFilterExpression, 1,
			myGlobals.device[i].netmask.s_addr) < 0)) {
	  if((pcap_setfilter(myGlobals.device[i].pcapPtr, &fcode) < 0)) {
	    traceEvent(CONST_TRACE_ERROR,
	  	    "Wrong filter '%s' (%s) on interface %s - using old filter",
		    myGlobals.runningPref.currentFilterExpression,
                       pcap_geterr(myGlobals.device[i].pcapPtr), myGlobals.device[i].name);
	  }
#ifdef HAVE_PCAP_FREECODE
          pcap_freecode(&fcode);
#endif
	}
      }
    }

    printFlagedWarning(err);
    if(myGlobals.runningPref.filterExpressionInExtraFrame)
        sendString("</BODY>\n</HTML>\n");
    else printHTMLtrailer();
    return 2;
  }
}

/* ******************************* */

/* Courtesy of Michael Weidel <michael.weidel@gmx.de> */

void changeFilter(void) {
  char buf[LEN_GENERAL_WORK_BUFFER];

  printHTMLheader("Change kernel (libpcap) filter expression", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<BR><HR><P><center>\n");
  sendString("<TABLE BORDER=1 "TABLE_DEFAULTS">\n<TR>\n");
  sendString("<TH "TH_BG" ALIGN=center>Old Filter Expression:&nbsp;</TH><TD ALIGN=left>");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<B>%s",
	     myGlobals.runningPref.currentFilterExpression);
  sendString(buf);
  if(*myGlobals.runningPref.currentFilterExpression == '\0') sendString("&lt;No filter defined&gt;");
  sendString("</B><BR>\n</TD>\n</TR>\n");

  sendString("<FORM METHOD=POST ACTION=/doChangeFilter>\n");
  sendString("<TR>\n<TH "TH_BG" ALIGN=center>New Filter Expression:&nbsp;</TH>");
  sendString("<TD ALIGN=left><INPUT TYPE=text NAME=filter SIZE=40>\n");
  sendString("</TD>\n</TR>\n");
  sendString("<TR><TD ALIGN=CENTER COLSPAN=2><INPUT TYPE=submit VALUE=\"Change Filter\">&nbsp;&nbsp;&nbsp;");
  sendString("<INPUT TYPE=reset  VALUE=Reset></TD></TR></FORM></TABLE>"TABLE_OFF"\n");

  sendString("</B><P></CENTER>\n<FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");
  sendString("You can use all filter expressions libpcap can handle, \n");
  sendString("like the ones you pass to tcpdump.<BR>\n");
  sendString("If \"new filter expression\" is left empty, no filtering is performed.<BR>\n");
  sendString("If you want the statistics to be reset, you have to do that manually ");
  sendString("with <A HREF=\"" CONST_RESET_STATS_HTML "\">Reset Stats</A>.<BR>\n");
  sendString("<B>Be careful</B>: That can take quite a long time!");
  sendString("<BR><B></FONT>\n");
}

/* *******************************/

struct _menuData {
  char	*text, *anchor;
};

static struct _menuData menuItem[] = {
  { "Show Users", CONST_SHOW_USERS_HTML },
  { "Add User",   CONST_ADD_USERS_HTML },
  { "Show URLs",  CONST_SHOW_URLS_HTML },
  { "Add URL",    CONST_ADD_URLS_HTML }
};

/* *******************************/

static void sendMenuFooter(int itm1Idx, int itm2Idx) {
  char	buf[128];

  sendString("<CENTER>\n");
  sendString("<FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
	     "[ <A HREF=/%s>%s</A> ]&nbsp;[ <A HREF=/%s>%s</A> ]\n",
	     menuItem[itm1Idx].anchor, menuItem[itm1Idx].text,
	     menuItem[itm2Idx].anchor, menuItem[itm2Idx].text);
  sendString(buf);
  sendString("</FONT>\n</CENTER>\n");
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
 /* 14 is ok for traditional crypt, but the enhanced crypt() in FreeBSD
  * (and others?) can be much larger. Just us a big buffer for ALL OSes
  * in case others change too...
  */
  char cpw[LEN_MEDIUM_WORK_BUFFER];
#endif

  /* Check existence of user 'admin' */
  key_data.dptr = key;
  key_data.dsize = strlen(key_data.dptr)+1;

  return_data = gdbm_fetch(myGlobals.pwFile, key_data);

  if((return_data.dptr == NULL) || (existingOK != 0)) {
    char *thePw, pw1[16], pw2[16];
    /* If not existing, then add user 'admin' and ask for password  */

    if(userQuestion != NULL) {
      if (myGlobals.runningPref.daemonMode) {
	/*
	 * We need a password for the admin user, but the user requested
	 * daemon mode.  stdin is already detached; getpass() would fail.
	 *
	 * Courtesy of Ambrose Li <a.c.li@ieee.org>
	 *
	 */
	traceEvent(CONST_TRACE_FATALERROR, "No password for admin user - please re-run ntop in non-daemon mode first");
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
    traceEvent(CONST_TRACE_INFO, "'%s' <-> '%s'", key, data_data.dptr);
#endif

    data_data.dsize = strlen(data_data.dptr)+1;
    gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE);

    /* Added user, clear the list */
    clearUserUrlList();

    /* print notice to the user */
    if(memcmp(key,"1admin",6) == 0)
      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Admin user password has been set");

#ifdef HAVE_CRYPTGETFORMAT
    if(memcmp(key,"1",1) == 0) {
      /* If we have the routine, store the crypt type too */
      char cgf[LEN_MEDIUM_WORK_BUFFER];
      key_data.dptr = "3admin";
      key_data.dsize = strlen(key_data.dptr)+1;
      strncpy(cgf, (char*)crypt_get_format(),  sizeof(cgf));
      cgf[sizeof(cgf)-1] = '\0';
      data_data.dptr = cgf;
      data_data.dsize = strlen(data_data.dptr)+1;
      gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE);
    }
#endif

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
  addKeyIfMissing("2configNtop", "users=1admin", 0, 0, NULL);
  addKeyIfMissing("2privacyFlag","users=1admin", 0, 0, NULL);
}

/* ************************************ */

/*
 * Initialize all preferences to their default values
 */
void initUserPrefs (UserPref *pref)
{
  pref->accessLogFile = DEFAULT_NTOP_ACCESS_LOG_FILE;
  pref->enablePacketDecoding   = DEFAULT_NTOP_PACKET_DECODING;
  pref->stickyHosts = DEFAULT_NTOP_STICKY_HOSTS;
  pref->daemonMode = DEFAULT_NTOP_DAEMON_MODE;
  pref->rFileName = DEFAULT_NTOP_TRAFFICDUMP_FILENAME;
  pref->trackOnlyLocalHosts    = DEFAULT_NTOP_TRACK_ONLY_LOCAL;
  pref->devices = DEFAULT_NTOP_DEVICES;
  pref->enableOtherPacketDump = DEFAULT_NTOP_OTHER_PKT_DUMP;
  pref->filterExpressionInExtraFrame = DEFAULT_NTOP_FILTER_IN_FRAME;
  pref->pcapLog = DEFAULT_NTOP_PCAP_LOG_FILENAME;
  pref->localAddresses = DEFAULT_NTOP_LOCAL_SUBNETS;
  pref->numericFlag = DEFAULT_NTOP_NUMERIC_IP_ADDRESSES;
  pref->dontTrustMACaddr = DEFAULT_NTOP_DONT_TRUST_MAC_ADDR;
  pref->protoSpecs = DEFAULT_NTOP_PROTO_SPECS;
  pref->enableSuspiciousPacketDump = DEFAULT_NTOP_SUSPICIOUS_PKT_DUMP;
  pref->refreshRate = DEFAULT_NTOP_AUTOREFRESH_INTERVAL;
  pref->disablePromiscuousMode = DEFAULT_NTOP_DISABLE_PROMISCUOUS;
  pref->traceLevel = DEFAULT_TRACE_LEVEL;
  pref->maxNumHashEntries = pref->maxNumSessions = (u_int)-1;
  pref->webAddr = DEFAULT_NTOP_WEB_ADDR;
  pref->webPort = DEFAULT_NTOP_WEB_PORT;
  pref->ipv4or6 = DEFAULT_NTOP_FAMILY;
  pref->enableSessionHandling  = DEFAULT_NTOP_ENABLE_SESSIONHANDLE;
  pref->currentFilterExpression = DEFAULT_NTOP_FILTER_EXPRESSION;
  strncpy((char *) &pref->domainName, DEFAULT_NTOP_DOMAIN_NAME, sizeof(pref->domainName));
  pref->flowSpecs = DEFAULT_NTOP_FLOW_SPECS;
  pref->debugMode = DEFAULT_NTOP_DEBUG_MODE;
#ifndef WIN32
  pref->useSyslog = DEFAULT_NTOP_SYSLOG;
#endif
  pref->mergeInterfaces = DEFAULT_NTOP_MERGE_INTERFACES;
#ifdef WIN32
  pref->pcapLogBasePath = strdup(_wdir);     /* a NULL pointer will
                                                        * break the logic */
#else
  pref->pcapLogBasePath = strdup(CFG_DBFILE_DIR);
#endif
  pref->spoolPath       = strdup("");              /* a NULL pointer will break the logic */
  pref->fcNSCacheFile   = DEFAULT_NTOP_FCNS_FILE;
  /* note that by default ntop will merge network interfaces */
  pref->mapperURL = DEFAULT_NTOP_MAPPER_URL;
#ifdef HAVE_OPENSSL
  pref->sslAddr = DEFAULT_NTOP_WEB_ADDR;
  pref->sslPort = DEFAULT_NTOP_WEB_PORT;
#endif
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
   pref->useSSLwatchdog = 0;
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
   pref->disableSchedYield = DEFAULT_NTOP_SCHED_YIELD;
#endif

   pref->w3c = DEFAULT_NTOP_W3C;
   pref->P3Pcp = DEFAULT_NTOP_P3PCP;
   pref->P3Puri = DEFAULT_NTOP_P3PURI;

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
   pref->setNonBlocking = DEFAULT_NTOP_SETNONBLOCK;
#endif
   pref->disableStopcap = DEFAULT_NTOP_DISABLE_STOPCAP;
   pref->disableInstantSessionPurge = DEFAULT_NTOP_DISABLE_IS_PURGE;
   pref->printIpOnly = DEFAULT_NTOP_PRINTIPONLY;
   pref->printFcOnly = DEFAULT_NTOP_PRINTFCONLY;
   pref->noInvalidLunDisplay = DEFAULT_NTOP_NO_INVLUN_DISPLAY;
   pref->disableMutexExtraInfo = DEFAULT_NTOP_DISABLE_MUTEXINFO;

   pref->skipVersionCheck = DEFAULT_NTOP_SKIP_VERSION_CHECK;
}

/* *******************************/
void copyUserPrefs (UserPref *from, UserPref *to)
{
        /* copy from admin to running */
        to->enablePacketDecoding = from->enablePacketDecoding;
        to->stickyHosts = from->stickyHosts;
        to->daemonMode = from->daemonMode;
        to->rFileName = from->rFileName;
        to->trackOnlyLocalHosts = from->trackOnlyLocalHosts;
        to->devices = from->devices;
        to->enableOtherPacketDump = from->enableOtherPacketDump;
        to->filterExpressionInExtraFrame = from->filterExpressionInExtraFrame;
        to->pcapLog = from->pcapLog;
        to->localAddresses = from->localAddresses;
        to->numericFlag = from->numericFlag;
        to->dontTrustMACaddr = from->dontTrustMACaddr;
        to->protoSpecs = from->protoSpecs;
        to->enableSuspiciousPacketDump = from->enableSuspiciousPacketDump;
        to->refreshRate = from->refreshRate;
        to->disablePromiscuousMode = from->disablePromiscuousMode;
        to->traceLevel = from->traceLevel;
        to->maxNumHashEntries = from->maxNumHashEntries;
        to->webAddr = from->webAddr;
        to->webPort = from->webPort;
        to->ipv4or6 = from->ipv4or6;
        to->enableSessionHandling = from->enableSessionHandling;
        to->currentFilterExpression = from->currentFilterExpression;
        strncpy((char *) &to->domainName,
                (char *)&from->domainName, sizeof(to->domainName));
        to->flowSpecs = from->flowSpecs;
        to->debugMode = from->debugMode;
#ifndef WIN32
        to->useSyslog = from->useSyslog;
#endif
        to->mergeInterfaces = from->mergeInterfaces;
#ifdef WIN32
        to->pcapLogBasePath = from->pcapLogBasePath;
#else
        to->pcapLogBasePath = from->pcapLogBasePath;
#endif
        to->spoolPath = from->spoolPath;
        to->fcNSCacheFile = from->fcNSCacheFile;
        to->mapperURL = from->mapperURL;
#ifdef HAVE_OPENSSL
        to->sslAddr = from->sslAddr;
        to->sslPort = from->sslPort;
#endif
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
        to->useSSLwatchdog = from->useSSLwatchdog;
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
        to->disableSchedYield = from->disableSchedYield;
#endif

        to->w3c = from->w3c;
        to->P3Pcp = from->P3Pcp;
        to->P3Puri = from->P3Puri;

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
        to->setNonBlocking = from->setNonBlocking;
#endif
        to->disableStopcap = from->disableStopcap;
        to->disableInstantSessionPurge = from->disableInstantSessionPurge;
        to->printIpOnly = from->printIpOnly;
        to->printFcOnly = from->printFcOnly;
        to->noInvalidLunDisplay = from->noInvalidLunDisplay;
        to->disableMutexExtraInfo = from->disableMutexExtraInfo;

        to->skipVersionCheck = from->skipVersionCheck;
}

/* *******************************/

#define NTOP_SAVE_PREFS     "SP"
#define NTOP_RESTORE_DEF    "RD"
#define CONFIG_STR_ENTRY(bg,title,name,size,configvalue,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s</td><td><INPUT NAME=%s SIZE=%d VALUE=%s><BR>%s</td></TR>", bg, title, name, size, (configvalue != NULL) ? configvalue : "", descr); \
        sendString (buf);

#define CONFIG_FILE_ENTRY(bg,title,name,size,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td><INPUT NAME=%s SIZE=%d VALUE=%s TYPE=FILE><BR>%s</TD></TR>", bg, title, name, size, (value != NULL) ? value : "(null)", descr); \
        sendString (buf);

#define CONFIG_INT_ENTRY(bg,title,name,size,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td><INPUT NAME=%s SIZE=%d VALUE=%d><BR>%s</TD></TR>", bg, title, name, size, value, descr); \
        sendString (buf);

#define CONFIG_CHKBOX_ENTRY(bg,title,name,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td><INPUT TYPE=checkbox NAME=%s VALUE=%d %s><BR>%s</TD></TR>", bg, title, name, value, value ? "CHECKED" : "", descr); \
        sendString (buf);


int processNtopConfigData (char *buf, int savePref)
{
    char *strtokState, *mainState, *token, *button;
    int startCap = FALSE, action;
    UserPref tmpPrefs, *pref = &myGlobals.savedPref;
    char tmp[3] = "0", *devices = NULL, foundDevices = 0;

    token = strtok_r(buf, "&", &mainState);
    tmpPrefs = myGlobals.savedPref;

    /* however, switch off all chkbox fields. If they've been set, they'll get
     * processed. If they stay turned off, it is a sign that they've been
     * unchecked and we need to handle this.
     */
    tmpPrefs.enableSessionHandling = tmpPrefs.enablePacketDecoding = 0;
    tmpPrefs.stickyHosts = tmpPrefs.trackOnlyLocalHosts = 0;
    tmpPrefs.disablePromiscuousMode = tmpPrefs.disableMutexExtraInfo = 0;
    tmpPrefs.disableInstantSessionPurge = tmpPrefs.disableStopcap = 0;
    tmpPrefs.debugMode = tmpPrefs.daemonMode = tmpPrefs.w3c = 0;
    tmpPrefs.noInvalidLunDisplay = tmpPrefs.filterExpressionInExtraFrame = 0;
    tmpPrefs.numericFlag = tmpPrefs.mergeInterfaces = 0;
#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
    tmpPrefs.setNonBlocking = 0;
#endif
    tmpPrefs.dontTrustMACaddr = 0;
    tmpPrefs.enableOtherPacketDump = tmpPrefs.enableSuspiciousPacketDump = 0;
    tmpPrefs.enableSessionHandling = 0;
#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
    tmpPrefs.useSSLwatchdog = 0;
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
    tmpPrefs.disableSchedYield = 0;
#endif

    devices = tmpPrefs.devices;
    tmpPrefs.devices = NULL;

    while(token != NULL) {
        char *key, *value;

        key = strtok_r(token, "=", &strtokState);
        if(key != NULL) value = strtok_r(NULL, "=", &strtokState); else value = NULL;

        /* traceEvent(CONST_TRACE_INFO, "RRD: key(%s)=%s", key, value);  */

        if(key) {
            action = processNtopPref (key, value, savePref, &tmpPrefs);

            if (action) {
                startCap = TRUE;
            }

	    if((!strcmp(key, NTOP_PREF_DEVICES)) || (!strcmp(key, "BASIC_PREFS")))
	      foundDevices = 1;
        }
        token = strtok_r(NULL, "&", &mainState);
    }

    if((tmpPrefs.devices == NULL) && (!foundDevices))
      tmpPrefs.devices = devices;
    else {
      if(devices != NULL) free(devices);      
    }

    if(tmpPrefs.devices == NULL) delPrefsValue(NTOP_PREF_DEVICES);

    /* Now we need to delete all the preferences that were unchecked.
     * Radio box & checkbox preferences that were set in a previous instance
     * but cleared in this instance will not appear in the POST data. So, if
     * the value has changed from what existed before, we need to remove them
     * from the saved preferences file.
     */
    if (myGlobals.savedPref.enableSessionHandling &&
        !tmpPrefs.enableSessionHandling) {
        /* default for enableSessionHandling is TRUE */
        processNtopPref (NTOP_PREF_EN_SESSION, FALSE, savePref, &tmpPrefs);

    }

    if (myGlobals.savedPref.enablePacketDecoding &&
        !tmpPrefs.enablePacketDecoding) {
        processNtopPref (NTOP_PREF_EN_PROTO_DECODE, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.stickyHosts && !tmpPrefs.stickyHosts) {
        processNtopPref (NTOP_PREF_STICKY_HOSTS, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.trackOnlyLocalHosts &&
        !tmpPrefs.trackOnlyLocalHosts) {
        processNtopPref (NTOP_PREF_TRACK_LOCAL, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.disablePromiscuousMode &&
        !tmpPrefs.disablePromiscuousMode) {
        processNtopPref (NTOP_PREF_NO_PROMISC, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.daemonMode && !tmpPrefs.daemonMode) {
        processNtopPref (NTOP_PREF_DAEMON, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.noInvalidLunDisplay &&
        !tmpPrefs.noInvalidLunDisplay) {
        processNtopPref (NTOP_PREF_NO_INVLUN, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.filterExpressionInExtraFrame &&
        !myGlobals.savedPref.filterExpressionInExtraFrame) {
        processNtopPref (NTOP_PREF_FILTER_EXTRA_FRM, FALSE, savePref,
                         &tmpPrefs);
    }

    if (myGlobals.savedPref.w3c && !tmpPrefs.w3c) {
        processNtopPref (NTOP_PREF_W3C, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.numericFlag && !tmpPrefs.numericFlag) {
        processNtopPref (NTOP_PREF_NUMERIC_IP, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.mergeInterfaces && !tmpPrefs.mergeInterfaces) {
        processNtopPref (NTOP_PREF_MERGEIF, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.disableInstantSessionPurge &&
        !tmpPrefs.disableInstantSessionPurge) {
        processNtopPref (NTOP_PREF_NO_ISESS_PURGE, FALSE, savePref, &tmpPrefs);
    }

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
    if (myGlobals.savedPref.setNonBlocking && !tmpPrefs.setNonBlocking) {
        processNtopPref (NTOP_PREF_NOBLOCK, FALSE, savePref, &tmpPrefs);
    }
#endif

    if (myGlobals.savedPref.disableStopcap && !tmpPrefs.disableStopcap) {
        processNtopPref (NTOP_PREF_NO_STOPCAP, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.dontTrustMACaddr && !tmpPrefs.dontTrustMACaddr) {
        processNtopPref (NTOP_PREF_NO_TRUST_MAC, FALSE, savePref, &tmpPrefs);
    }

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
    if (myGlobals.savedPref.useSSLwatchdog && !tmpPrefs.useSSLwatchdog) {
        processNtopPref (NTOP_PREF_USE_SSLWATCH, FALSE, savePref, &tmpPrefs);
    }
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
    if (myGlobals.savedPref.disableSchedYield && !tmpPrefs.disableSchedYield) {
        processNtopPref (NTOP_PREF_NO_SCHEDYLD, FALSE, savePref, &tmpPrefs);
    }
#endif

    if (myGlobals.savedPref.debugMode && !tmpPrefs.debugMode) {
        processNtopPref (NTOP_PREF_DBG_MODE, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.enableOtherPacketDump &&
        !tmpPrefs.enableOtherPacketDump) {
        processNtopPref (NTOP_PREF_DUMP_OTHER, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.enableSuspiciousPacketDump &&
        !tmpPrefs.enableSuspiciousPacketDump) {
        processNtopPref (NTOP_PREF_DUMP_SUSP, FALSE, savePref, &tmpPrefs);
    }

    if (myGlobals.savedPref.disableMutexExtraInfo &&
        !tmpPrefs.disableMutexExtraInfo) {
        processNtopPref (NTOP_PREF_NO_MUTEX_EXTRA, FALSE, savePref, &tmpPrefs);
    }

    /* Copy over the preferences now */
    myGlobals.savedPref = tmpPrefs;

    return (startCap);
}

void printNtopConfigHeader (char *url, UserPrefDisplayPage configScr)
{
    char buf[1024];
    char theLink[32];

    safe_snprintf (__FILE__, __LINE__, theLink, sizeof(theLink),
                   "/configNtop.html?&showD=");

    switch (configScr) {
    case showPrefBasicPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <B>Basic Preferences</B> ]&nbsp;"
                      "[ <A HREF=%s2>Display Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s3>IP Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s4>FC Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s5>Advanced Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s6>Debugging Preferences</A> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;

    case showPrefDisplayPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <A HREF=%s1>Basic Preferences</A> ]&nbsp;"
                      "[ <B>Display Preferences</B> ]&nbsp;"
                      "[ <A HREF=%s3>IP Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s4>FC Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s5>Advanced Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s6>Debugging Preferences</A> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;
    case showPrefIPPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <A HREF=%s1>Basic Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s2>Display Preferences</A> ]&nbsp;"
                      "[ <B>IP Preferences</B> ]&nbsp;"
                      "[ <A HREF=%s4>FC Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s5>Advanced Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s6>Debugging Preferences</A> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;
    case showPrefFCPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <A HREF=%s1>Basic Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s2>Display Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s3>IP Preferences</A> ]&nbsp;"
                      "[ <B>FC Preferences</B> ]&nbsp;"
                      "[ <A HREF=%s5>Advanced Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s6>Debugging Preferences</A> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;
    case showPrefAdvPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <A HREF=%s1>Basic Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s2>Display Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s3>IP Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s4>FC Preferences</A> ]&nbsp;"
                      "[ <B>Advanced Preferences</B> ]&nbsp;"
                      "[ <A HREF=%s6>Debugging Preferences</A> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;
    case showPrefDbgPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <A HREF=%s1>Basic Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s2>Display Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s3>IP Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s4>FC Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s5>Advanced Preferences</A> ]&nbsp;"
                      "[ <B>Debugging Preferences</B> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;
    case showPrefPluginPref:
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
                      "[ <A HREF=%s1>Basic Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s2>Display Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s3>IP Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s4>FC Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s5>Advanced Preferences</A> ]&nbsp;"
                      "[ <A HREF=%s6>Debugging Preferences</A> ]&nbsp;</p>"
                      "[ <B>Plugin Preferences</B> ]&nbsp;</p>",
                      theLink, theLink, theLink, theLink, theLink, theLink);
        break;
    }

    sendString (buf);

    safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf),
                   "<FORM ACTION = %s%d method=POST>"
                   " <TABLE BORDER=1 "TABLE_DEFAULTS">\n"
                   "<TR><TH ALIGN=CENTER "DARK_BG">Preference</TH>"
                   "<TH ALIGN=CENTER "DARK_BG">Configured Value</TH></TR>",
                   theLink, configScr);
    sendString (buf);
}

/* ***************************************************** */

#ifdef WIN32
char * rindex(const char *p, int ch); /* Prototype */

char * rindex(const char *p, int ch) {
  union {
    const char *cp;
    char *p;
  } u;
  char *save;
  
  u.cp = p;
  for (save = NULL;; ++u.p) {
    if (*u.p == ch)
      save = u.p;
    if (*u.p == '\0')
      return(save);
  }
  /* NOTREACHED */
}
#endif

/* ***************************************************** */

void handleNtopConfig (char* url, UserPrefDisplayPage configScr, int postLen)
{
    char buf[1024], hostStr[MAXHOSTNAMELEN+16];
    bool action = FALSE, startCap = FALSE;
    int len;
    UserPref defaults, *pref;

    /*
     * Configuration is dealt with via POST method. So read the data first.
     */
    if (postLen) {
        if ((len = readHTTPpostData (postLen, buf, 1024)) != postLen) {
            traceEvent (CONST_TRACE_WARNING, "handleNtopConfig: Unable to retrieve "
                        "all POST data (%d, expecting %d). Aborting processing\n",
                        len, postLen);
        }
        else {
            /* =============================================
             * Parse input URI & store specified preferences
             * =============================================
             */
            char *token;
            int savePref = FALSE, restoreDef = FALSE;

            /* =============================================
             * Parse input URI & store specified preferences
             * =============================================
             */

            if((buf != NULL) && (buf [0] != '\0')) {
                unescape_url(buf);

		/* traceEvent (CONST_TRACE_INFO, "BUF='%s'\n", buf); */

               /* locate the last parameter which tells us which button got pressed */
                if ((token = rindex (buf, '&')) != NULL) {
                    token++;
                    if (strncmp (token, NTOP_SAVE_PREFS,
                                 strlen (NTOP_SAVE_PREFS)) == 0) {
                        savePref = TRUE;
                    }
                    else if (strncmp (token, NTOP_RESTORE_DEF,
                                      strlen (NTOP_RESTORE_DEF)) == 0) {
                        restoreDef = TRUE;
                    }
                }

                if (restoreDef) {
                    initUserPrefs (&defaults);
                    pref = &defaults;
                }
                else {
                    /* process preferences and start capture if necessary */
                    processNtopConfigData (buf, savePref);
                    if (startCap) {
                        /* TBD */
                    }
                }
            }
        }
    }

    /* =========================================
     * Display preferences page & current values
     * =========================================
     */
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("Configure NTOP", NULL, 0);

    sendString ("<CENTER>\n");

    printNtopConfigHeader (url, configScr);

    switch (configScr) {
    case showPrefBasicPref:
      {
	pcap_if_t *devpointer;
	int i, rc;
	char ebuf[CONST_SIZE_PCAP_ERR_BUF];

	sendString("<TR><INPUT TYPE=HIDDEN NAME=BASIC_PREFS VALUE=1><TD ALIGN=LEFT "DARK_BG">Capture Interfaces (-i)</TD><TD>\n");
	if(((rc = pcap_findalldevs(&devpointer, ebuf)) >= 0) && (devpointer != NULL)) {

	  for (i = 0; devpointer != 0; i++) {
	    if(strcmp(devpointer->name, "any")) {
	      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			    "<INPUT TYPE=checkbox NAME=\"%s\" VALUE=\"%s\" %s>%s (%s)<br>\n",
			    NTOP_PREF_DEVICES, devpointer->name, 
			    (pref->devices && strstr(pref->devices, devpointer->name)) ? "CHECKED" : "", 
			    devpointer->name,
			    devpointer->description ? devpointer->description : devpointer->name);
	      sendString(buf);
	    }
	  
	    devpointer = devpointer->next;
	  }

	  pcap_freealldevs(devpointer);
	} else {
	  /*
	    traceEvent(CONST_TRACE_INFO, "pcap_findalldevs failed [rc=%d][%s]\n", 
	    rc, ebuf);
	  */
	}
	sendString("</TD></TR>");
      }

        CONFIG_STR_ENTRY (DARK_BG, "Capture File Path (-f)", NTOP_PREF_CAPFILE, 50,
                          pref->rFileName,
                          "Capture file to read from (takes precedence over "
                          "interface specification)");

        CONFIG_STR_ENTRY (DARK_BG, "Capture Filter Expression (-B)",
                          NTOP_PREF_FILTER,
                          50, pref->currentFilterExpression,
                          "Restrict the traffic seen by ntop. BPF syntax.");

        if (pref->webAddr == NULL) {
            safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
                           "%d", pref->webPort);
        }
        else {
            safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
                           "%s:%d", pref->webAddr, pref->webPort);
        }
        CONFIG_STR_ENTRY (DARK_BG, "HTTP Server (-w)", NTOP_PREF_WEBPORT,
                          50, hostStr,
                          "HTTP Server [Address:]Port of ntop's web interface");

#ifdef HAVE_OPENSSL
        if (pref->sslAddr == NULL) {
            safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
                           "%d", pref->sslPort);
        }
        else {
            safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
                           "%s:%d", pref->sslAddr, pref->sslPort);
        }
        CONFIG_STR_ENTRY (DARK_BG, "HTTPS Server (-W)", NTOP_PREF_SSLPORT, 50,
                          hostStr, "HTTPS Server [Address:]Port of ntop's web "
                          "interface");
#endif

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Enable Session Handling (-z)",
                             NTOP_PREF_EN_SESSION,
                             pref->enableSessionHandling, "");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Enable Protocol Decoders (-b)",
                             NTOP_PREF_EN_PROTO_DECODE,
                             pref->enablePacketDecoding, "");

        CONFIG_STR_ENTRY (DARK_BG, "Flow Spec (-F)", NTOP_PREF_FLOWSPECS, 50,
                          pref->flowSpecs,
                          "Flow is a stream of captured packets that match a specified rule");

        CONFIG_STR_ENTRY (DARK_BG, "Local Subnet Address (-m)",
                          NTOP_PREF_LOCALADDR, 15,
                          pref->localAddresses,
                          "Local subnets in ntop reports. Mandatory for packet capture files");

        CONFIG_STR_ENTRY (DARK_BG, "Spool File Path (-Q)", NTOP_PREF_SPOOLPATH, 50,
                          pref->spoolPath,
                          "Location where temporary Ntop DB files are stored");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Sticky Hosts (-c)",
                             NTOP_PREF_STICKY_HOSTS, pref->stickyHosts,
                             "Don't purge idle hosts from memory");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Track Local Hosts (-g)",
                             NTOP_PREF_TRACK_LOCAL,
                             pref->trackOnlyLocalHosts,
                             "Capture data only about local hosts");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Disable Promiscuous Mode (-s)",
                             NTOP_PREF_NO_PROMISC,
                             pref->disablePromiscuousMode,
                             "Don't set the interface(s) into promiscuous mode");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Run as daemon (-d)", NTOP_PREF_DAEMON,
                             pref->daemonMode, "Run Ntop as a daemon");
        break;

    case showPrefDisplayPref:
        CONFIG_INT_ENTRY (DARK_BG, "Refresh Time (-r)", NTOP_PREF_REFRESH_RATE,
                          5, pref->refreshRate,
                          "Delay (in secs) between automatic screen updates for "
                          "supported HTML pages");

        CONFIG_INT_ENTRY (DARK_BG, "Max Table Rows (-e)", NTOP_PREF_MAXLINES, 5,
                          pref->maxNumLines,
                          "Max number of lines that ntop will display on each "
                          " generated HTML page");

        sendString("<TR><TD ALIGN=LEFT "DARK_BG">Show Menus For</TD><TD>");
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<INPUT TYPE=radio NAME=%s  VALUE=%d %s>IP\n",
                      NTOP_PREF_PRINT_FCORIP, NTOP_PREF_VALUE_PRINT_IPONLY,
                      (pref->printIpOnly) ? "CHECKED" : "");
        sendString(buf);

        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<INPUT TYPE=radio NAME=%s VALUE=%d %s>FC\n",
                      NTOP_PREF_PRINT_FCORIP, NTOP_PREF_VALUE_PRINT_FCONLY,
                      (pref->printFcOnly) ? "CHECKED" : "");
        sendString(buf);

        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<INPUT TYPE=radio NAME=%s VALUE=%d %s>Both\n",
                      NTOP_PREF_PRINT_FCORIP, NTOP_PREF_VALUE_PRINT_BOTH,
                      (!pref->printIpOnly && !pref->printFcOnly) ? "CHECKED" : "");
        sendString(buf);
	sendString("</TD></TR>");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "No Info On Invalid LUNs",
                             NTOP_PREF_NO_INVLUN,
                             pref->noInvalidLunDisplay,
                             "Don't display info about non-existent LUNs");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Show Filter In Separate Frame (-k)",
                             NTOP_PREF_FILTER_EXTRA_FRM,
                             pref->filterExpressionInExtraFrame,
                             "Filter expression is in a separate frame and so "
                             "always visible");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Use W3C", NTOP_PREF_W3C,
                             pref->w3c,
                             "Generate 'BETTER' (but not perfect) w3c "
                             "compliant html 4.01 output");
        break;

    case showPrefIPPref:
        sendString("<TR><TD ALIGN=LEFT "DARK_BG">Use IPv4 or IPv6 (-4/-6)</TD><TD>");
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<INPUT TYPE=radio NAME=%s VALUE=%d %s>v4\n",
                      NTOP_PREF_IPV4V6, NTOP_PREF_VALUE_AF_INET,
                      (pref->ipv4or6 == AF_INET) ? "CHECKED" : "");
        sendString(buf);

        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<INPUT TYPE=radio NAME=%s VALUE=%d %s>v6\n",
                      NTOP_PREF_IPV4V6, NTOP_PREF_VALUE_AF_INET6,
                      (pref->ipv4or6 == AF_INET6) ? "CHECKED" : "");
        sendString(buf);

        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
                      "<INPUT TYPE=radio NAME=%s VALUE=%d %s>Both\n",
                      NTOP_PREF_IPV4V6, NTOP_PREF_VALUE_AF_BOTH,
                      (pref->ipv4or6 == AF_UNSPEC) ? "CHECKED" : "");
        sendString(buf);

        CONFIG_STR_ENTRY (DARK_BG, "Local Domain Name (-D)",
                          NTOP_PREF_DOMAINNAME, 10, pref->domainName,
                          "Only if ntop is having difficulty determining it "
                          "from the interface or in case of capture files");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "No DNS (-n)", NTOP_PREF_NUMERIC_IP,
                             pref->numericFlag, "Skip DNS resolution, showing "
                             "only numeric IP addresses");

        CONFIG_STR_ENTRY (DARK_BG, "TCP/UDP Protocols To Monitor (-p)",
                          NTOP_PREF_PROTOSPECS, 50, pref->protoSpecs,
                          "format is &lt;label&gt;=&lt;protocol list&gt; [, &lt;"
                          "label&gt;=&lt;protocol list&gt;] OR a filename"
                          "of a file containing such a format");
        CONFIG_STR_ENTRY (DARK_BG, "P3P-CP", NTOP_PREF_P3PCP, 50,
                          pref->P3Pcp,
                          "Return value for p3p compact policy header");

        CONFIG_STR_ENTRY (DARK_BG, "P3P-URI", NTOP_PREF_P3PURI, 50,
                          pref->P3Puri,
                          "Return value for p3p policyref header");

        CONFIG_STR_ENTRY (DARK_BG, "Host Mapper URL (-U)", NTOP_PREF_MAPPERURL,
                          50, pref->mapperURL,
                          "URL of the mapper.pl utility, for looking up geographical "
                          "location of the host");
        break;

    case showPrefFCPref:
        CONFIG_STR_ENTRY (DARK_BG, "WWN Mapper File (-N)", NTOP_PREF_WWN_MAP,
                          50, pref->fcNSCacheFile,
                          "Location of file mapping VSAN/FC_ID to WWN/Alias");
        break;

    case showPrefAdvPref:
        CONFIG_INT_ENTRY (DARK_BG, "Max Hashes (-x)", NTOP_PREF_MAXHASH, 5,
                          pref->maxNumHashEntries,
                          "Limit number of hash entries created for sessions and"
                          " hosts to limit memory used by ntop");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Don't Merge Interfaces (-M)",
                             NTOP_PREF_MERGEIF, pref->mergeInterfaces,
                             "Don't merge data from all interfaces");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "No Instant Session Purge",
                             NTOP_PREF_NO_ISESS_PURGE,
                             pref->disableInstantSessionPurge,
                             "Makes ntop respect the timeouts for completed "
                             "sessions");

#if !defined(WIN32) && defined(HAVE_PCAP_SETNONBLOCK)
        CONFIG_CHKBOX_ENTRY (DARK_BG, "Set Pcap to Nonblocking",
                             NTOP_PREF_NOBLOCK, pref->setNonBlocking,
                             "On platforms without select(). <B>Increases CPU usage "
                             "significantly</B>");
#endif
        CONFIG_CHKBOX_ENTRY (DARK_BG, "No web on memory error",
                             NTOP_PREF_NO_STOPCAP, pref->disableStopcap,
                             "Change default of having the web interface available "
                             "albeit with static content until ntop is shutdown");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Don't Trust MAC Address (-o)",
                             NTOP_PREF_NO_TRUST_MAC, pref->dontTrustMACaddr,
                             "Situations which may require this option include "
                             "port/VLAN mirror");

        CONFIG_STR_ENTRY (DARK_BG, "Pcap Log Base Path (-O)",
                          NTOP_PREF_PCAP_LOGBASE, 50, pref->pcapLogBasePath,
                          "Directory where packet dump files are created");

#ifdef MAKE_WITH_SSLWATCHDOG_RUNTIME
        CONFIG_CHKBOX_ENTRY (DARK_BG, "Use SSL Watchdog",
                             NTOP_PREF_USE_SSLWATCH, pref->useSSLwatchdog,
                             "");
#endif

#if defined(CFG_MULTITHREADED) && defined(MAKE_WITH_SCHED_YIELD)
        CONFIG_CHKBOX_ENTRY (DARK_BG, "Disable SchedYield",
                             NTOP_PREF_NO_SCHEDYLD, pref->disableSchedYield,
                             "");
#endif
        break;

    case showPrefDbgPref:
        CONFIG_CHKBOX_ENTRY (DARK_BG, "Run in debug mode (-K)",
                             NTOP_PREF_DBG_MODE, pref->debugMode,
                             "Simplifies debugging Ntop");

        CONFIG_INT_ENTRY (DARK_BG, "Trace Level (-t)", NTOP_PREF_TRACE_LVL, 5,
                          pref->traceLevel,
                          "Level of detailed messages ntop will display");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Save Other Packets (-j)",
                             NTOP_PREF_DUMP_OTHER, pref->enableOtherPacketDump,
                             "Useful for understanding packets unclassified by "
                             "Ntop");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Save Suspicious Packets (-q)",
                             NTOP_PREF_DUMP_SUSP,
                             pref->enableSuspiciousPacketDump,
                             "Create a dump file (pcap) of suspicious packets");

        CONFIG_STR_ENTRY (DARK_BG, "Log HTTP Requests (-a)",
                          NTOP_PREF_ACCESS_LOG, 50, pref->accessLogFile,
                          "Request HTTP logging and specify the location of the "
                          "log file");

#ifndef WIN32
        CONFIG_INT_ENTRY (DARK_BG, "Use Syslog (-L)", NTOP_PREF_USE_SYSLOG, 5,
                          pref->useSyslog,
                          "Send log messages to the system log instead of stdout");
#endif

        CONFIG_STR_ENTRY (DARK_BG, "Write captured frames to (-l)",
                          NTOP_PREF_PCAP_LOG, 50, pref->pcapLog,
                          "Causes a dump file to be created of the captured by "
                          "ntop in libpcap format");

        CONFIG_CHKBOX_ENTRY (DARK_BG, "Disable Extra Mutex Info",
                             NTOP_PREF_NO_MUTEX_EXTRA,
                             pref->disableMutexExtraInfo,
                             "Disables storing of extra information about the locks"
                             " and unlocks of the protective mutexes Ntop uses");
        break;
    }

    sendString ("</TABLE>");
    /* Save Preferences */
    if (configScr == showPrefDisplayPref) {
        sendString("<tr><td colspan=\"2\" align=\"center\">&nbsp;<p>"
                   "<input type=submit name=SP value=\"Save&nbsp;Preferences\">&nbsp;"
                   "<input type=submit name=AP value=\"Apply&nbsp;Preferences\">&nbsp;"
                   "<input type=submit name=RD value=\"Restore&nbsp;Defaults\">"
                   "</td></tr></table>\n"
                   "</form>\n<p></center>\n");
    }
    else {
        sendString("<tr><td colspan=\"2\" align=\"center\">&nbsp;<p>"
                   "<input type=submit name=SP value=\"Save&nbsp;Preferences\">&nbsp;"
                   "<input type=submit name=RD value=\"Restore&nbsp;Defaults\">"
                   "</td></tr></table>\n"
                   "</form>\n<p></center>\n");
    }

    sendString ("<P Align=CENTER><FONT COLOR = \"FF00FF\">Settings take effect at next startup</FONT></CENTER><P>");
    sendString ("<P Align=CENTER><FONT COLOR = \"FF00FF\">See <a href = \"info.html\">Show Configuration</A> for runtime values</FONT></CENTER><P>");

    printHTMLtrailer();
}
