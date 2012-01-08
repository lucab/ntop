/*
 *  Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
 *
 *			    http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
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
static int processNtopConfigData (char *buf, int savePref);

/* ****************************** */

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
                      "<img class=tooltip alt=\"Modify User\" src=\"/"CONST_EDIT_IMG"\" "
                        "border=\"0\" align=\"absmiddle\"></a>"
                      "&nbsp;</td></tr></th></tr>\n",
                      &key_data.dptr[1], CONST_MODIFY_USERS, key_data.dptr);
      } else{
	char ebuf[256];
	encodeWebFormURL(key_data.dptr, ebuf, sizeof(ebuf));

	safe_snprintf(__FILE__, __LINE__, buf, LEN_GENERAL_WORK_BUFFER,
                      "<tr><th "TH_BG" align=\"left\"><img src=\"/user.gif\">"
                      "&nbsp;%s</tg><td "TD_BG"><a href=\"/%s?%s\">"
                      "<img class=tooltip alt=\"Modify User\" src=\"/"CONST_EDIT_IMG"\" border=\"0\" "
                          "align=\"absmiddle\"></a>"
                      "&nbsp;<A HREF=/%s?%s>"
                      "<img class=tooltip alt=\"Delete User\" src=\"/deleteUser.gif\" border=\"0\" "
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

/* ****************************** */

void clearUserUrlList(void) {
  int i;

  /*
   * We just changed the database.
   * Delete the in-memory copy so next time we reference it,
   * it will be reloaded with the new values
   */

  traceEvent(CONST_TRACE_NOISY, "SECURITY: Loading items table");

  if(myGlobals.securityItemsMutex.isInitialized == 1)
    accessMutex(&myGlobals.securityItemsMutex, "clear");

  for (i=0; i<myGlobals.securityItemsLoaded; i++) {
    free(myGlobals.securityItems[i]);
  }
  myGlobals.securityItemsLoaded = 0;

  if(myGlobals.securityItemsMutex.isInitialized == 1)
    releaseMutex(&myGlobals.securityItemsMutex);
}

/* ****************************** */

void addUser(char* user) {
  char tmpStr[128];

  printHTMLheader("Manage ntop Users", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR><P>\n");

  if((user != NULL) && ((strlen(user) < 2) || (user[0] != '1'))) {
    printFlagedWarning("<I>The specified username is invalid.</I>");
  } else {
    sendString("<CENTER>\n");

    sendString("<script Language=\"JavaScript\">\nfunction CheckForm(theForm) "
	       "{\nif(theForm.pw.value != theForm.pw1.value) {\n    alert(\"Passwords do not match. "
	       "Please try again.\");\n    theForm.pw1.focus();\n    return(false);\n  }\n  return(true);"
	       "\n}\n</script>\n");

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
    sendString("<TR><TH ALIGN=right>Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw SIZE=20></TD></TR>\n");
    sendString("<TR><TH ALIGN=right>Verify Password:&nbsp;</TH>"
	       "<TD ALIGN=left><INPUT TYPE=password NAME=pw1 SIZE=20></TD></TR>\n");

    /*********** Communities **********/

    {
      int i, numUsers=0, len = strlen(COMMUNITY_PREFIX);
      datum key_data, return_data;
      char *aubuf=NULL, *userCommunities[20], communities[128], key[256];

      sendString("<TR><TH ALIGN=right VALIGN=top>Authorised Communities:&nbsp;</TH>"
		 "<TD ALIGN=left>\n<SELECT NAME=communities MULTIPLE>\n");

      memset(userCommunities, 0, sizeof(userCommunities));

      if(user != NULL) {
	snprintf(key, sizeof(key), "%s%s", COMMUNITY_PREFIX, &user[1]);

	if(fetchPwValue(key, communities, sizeof(communities)) == 0) {
	  char *strtokState, *item;

	  item = strtok_r(communities, "&", &strtokState);
	  for(i=0; (item != NULL) && (i < sizeof(userCommunities)-1); i++) {
	    userCommunities[i] = item;
	    item = strtok_r(NULL, "&", &strtokState);
	  }

	  if(item != NULL)
	    traceEvent(CONST_TRACE_ERROR, "Too many communities for user='%s'", &user[1]);

	  userCommunities[i] = NULL;
	}
      }

      return_data = gdbm_firstkey(myGlobals.prefsFile);

      while(return_data.dptr != NULL) {
	key_data = return_data;

	if(!strncmp(key_data.dptr, COMMUNITY_PREFIX, len)) {
	  int found = 0;
	  char *communityName = &key_data.dptr[len];

	  for(i=0; userCommunities[i] != NULL; i++)
	    if(strcmp(userCommunities[i], communityName) == 0) {
	      found = 1;
	  }

	  /* Make sure that at least a user is selected */
	  if((numUsers == 0) && (userCommunities[0] == NULL)) found = 1;

	  safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
			"<option value=%s %s>%s</option>\n",
			communityName,
			found ? "SELECTED" : "",
			communityName);
	  sendString(tmpStr);
	  numUsers++;
	}

	return_data = gdbm_nextkey(myGlobals.prefsFile, key_data);
	free(key_data.dptr);
      }

      if(aubuf != NULL) free(aubuf); /* (**) */

      sendString("</SELECT>\n</TD></TR>\n");
    }


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

/* ****************************** */

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
/* ****************************** */

#define MAX_NUM_COMMUNITIES     32

void doAddUser(int len) {
  char *err=NULL, key_str[64], value_str[256];
  int j;

  if(len <= 0) {
    err = "ERROR: both user and password must be non empty fields.";
  } else {
    char postData[256], *key, *user=NULL, *pw=NULL, *communities[MAX_NUM_COMMUNITIES];
    int i, idx, badChar=0, num_communities = 0;

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
	else if(strcmp(key, "communities") == 0) {
	  if(num_communities+1 < MAX_NUM_COMMUNITIES) {
	    communities[num_communities] = strdup(&postData[i+1]);

	    for(j=0; j<strlen(communities[num_communities]); j++)
	      if(communities[num_communities][j] == '&') {
		communities[num_communities][j] = '\0';
		break;
	      }

	    num_communities++;
	  }
	}
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

      snprintf(key_str, sizeof(key_str), "%s%s", COMMUNITY_PREFIX, user);
      value_str[0] = '\0';

      if(num_communities > 0) {
	strcat(value_str, communities[0]);

	for(j=1; j<num_communities; j++) {
	  strcat(value_str, "&");
	  strcat(value_str, communities[j]);
	}

	//traceEvent(CONST_TRACE_INFO, "========-----> [%s][%s]", key_str, value_str);
	storePwValue(key_str, value_str);
      }

      if(gdbm_store(myGlobals.pwFile, key_data, data_data, GDBM_REPLACE) != 0)
	err = "FATAL ERROR: unable to add the new user.";

      /* Added user, clear the list */
      clearUserUrlList();
    }
  }

if(err != NULL) {
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("ntop: Add/Modify User", NULL, BITFLAG_HTML_NO_REFRESH);
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
		    "<IMG CLASS=TOOLTIP ALT=\"Modify URL\" SRC=/"CONST_EDIT_IMG" BORDER=0 align=absmiddle></A>"
		    "&nbsp;<A HREF=/%s?%s><IMG CLASS=TOOLTIP ALT=\"Delete URL\" SRC=/deleteUser.gif BORDER=0 align=absmiddle>"
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

/* ****************************** */

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

    /*********** Users **********/
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

    if(aubuf != NULL) free(aubuf); /* (**) */

    sendString("</SELECT>\n</TD></TR>\n");

    if(url == NULL)
      sendString( "<tr><td colspan=2 align=left><U>NOTE</U>: if you leave the URL field empty then the "
		 "access is restricted to <I>all</I> ntop pages, otherwise,<br>this "
		 "entry matches all the pages begining with the specified string.</B>\n"
		  "</td>\n</tr>\n");

    sendString("</TABLE>"TABLE_OFF"\n");

    safe_snprintf(__FILE__, __LINE__, tmpStr, sizeof(tmpStr),
	     "<INPUT TYPE=submit VALUE=\"%s\">&nbsp;&nbsp;&nbsp;<INPUT TYPE=reset VALUE=Reset>\n",
	     (url != NULL) ? "Modify URL" : "Add URL");
    sendString(tmpStr);

    sendString("</FORM>\n");
    sendString("</CENTER>\n");
  }
  sendMenuFooter(0, 2);
}

/* ****************************** */

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

/* ****************************** */

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

/* ********************************* */

void setPcapFilter(char* filters, int device_id) {
  if(filters != NULL) {
    char *filters_copy;
    char buf[2048];

    if(filters[0] == '@') {
      /* This is a file */
      filters_copy = read_file(filters, buf, sizeof(buf));
      if(filters_copy)
	filters_copy = strdup(buf);
    } else
      filters_copy = strdup(filters);

    if(filters_copy) {
      char find_token[32], *the_filter;

      /* 
	 Format is
	 eth0="filter for eth0",eth1="filter for eth1"....
	 or
	 "filter for all interfaces"
      */

      if(strstr(filters_copy, "=") == NULL) {
	/* This is a filter for all interfaces */
	the_filter = filters_copy;

      } else {
	safe_snprintf(__FILE__, __LINE__,
		      find_token, sizeof(find_token), 
		      "%s=", myGlobals.device[device_id].name);
		
	the_filter = strstr(filters_copy, find_token);
	if(the_filter != NULL) {
	  /* We have an interface specific filter */
	  char *quote;
	  
	  the_filter += strlen(find_token);	  

	  quote = strchr(the_filter, ',');
	  if(quote != NULL) quote[0] = '\0';	  
	} else {
	  traceEvent(CONST_TRACE_INFO, 
		     "No filter specified for interface %s", 
		     myGlobals.device[device_id].name);
	  return;
	}
      }

      if(the_filter != NULL) {
	struct bpf_program fcode;

	traceEvent(CONST_TRACE_INFO, 
		   "Using filter '%s' for interface %s", 
		   the_filter, myGlobals.device[device_id].name);

	if(myGlobals.device[device_id].pcapPtr
	   && (!myGlobals.device[device_id].virtualDevice)) {
	  if((pcap_compile(myGlobals.device[device_id].pcapPtr, &fcode,
			   the_filter, 1,
			   myGlobals.device[device_id].netmask.s_addr) < 0)
	     || (pcap_setfilter(myGlobals.device[device_id].pcapPtr, &fcode) < 0)) {
	    traceEvent(CONST_TRACE_ERROR,
		       "Wrong filter '%s' (%s) on interface %s",
		       the_filter,
		       pcap_geterr(myGlobals.device[device_id].pcapPtr),
		       myGlobals.device[device_id].name);
	  } else {
	    pcap_freecode(&fcode);

	    if(*the_filter!='\0') {
	      traceEvent(CONST_TRACE_ALWAYSDISPLAY, "Set filter \"%s\" on interface %s",
			 the_filter, myGlobals.device[device_id].name);
	    } else {
	      traceEvent(CONST_TRACE_ALWAYSDISPLAY, 
			 "Set no kernel (libpcap) filtering on interface %s",
			 myGlobals.device[device_id].name);
	    }
	  }
	}       
      }
      
      free(filters_copy);
    }
  }
}

/* ****************************** */

/* Courtesy of Michael Weidel <michael.weidel@gmx.de> */

int doChangeFilter(int len) {
  int i,idx,badChar=0;
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
  } else 
    err = "ERROR: The HTTP Post Data was invalid.";

  if(badChar)
    err = "ERROR: the specified filter expression contains invalid characters.";

  if(err == NULL) {
    traceEvent(CONST_TRACE_INFO, "Changing the kernel (libpcap) filter...");

    for(i=0; i<myGlobals.numDevices; i++)
      setPcapFilter(myGlobals.runningPref.currentFilterExpression, i);
  }

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);

  printHTMLheader("changing kernel (libpcap) filter expression", NULL, BITFLAG_HTML_NO_REFRESH);
  sendString("<P><HR></P>\n<P><CENTER>");
  sendString("<FONT FACE=\"Helvetica, Arial, Sans Serif\">\n");

  if(err == NULL) {
    if(*myGlobals.runningPref.currentFilterExpression != '\0'){
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
		  "<B>Filter changed to <I>%s</I>.</B></FONT>\n",
		 myGlobals.runningPref.currentFilterExpression);
      sendString(buf);
    } else {
      sendString("<B>Kernel (libpcap) filtering disabled.</B></FONT>\n");
    }

    sendString("</CENTER></P>\n");
    printHTMLtrailer();

    if(currentFilterExpressionSav != NULL)
      free(currentFilterExpressionSav);

    return 0;
  }

  if(myGlobals.runningPref.currentFilterExpression != NULL)
    free(myGlobals.runningPref.currentFilterExpression);

  /* restore old filter expression */
  myGlobals.runningPref.currentFilterExpression = currentFilterExpressionSav;
  for(i=0; i<myGlobals.numDevices; i++)
    setPcapFilter(myGlobals.runningPref.currentFilterExpression, i); 

  printFlagedWarning(err);
  printHTMLtrailer();
  return 2;
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

/* ****************************** */

struct _menuData {
  char	*text, *anchor;
};

static struct _menuData menuItem[] = {
  { "Show Users", CONST_SHOW_USERS_HTML },
  { "Add User",   CONST_ADD_USERS_HTML },
  { "Show URLs",  CONST_SHOW_URLS_HTML },
  { "Add URL",    CONST_ADD_URLS_HTML }
};

/* ****************************** */

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

/* ****************************** */

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

/* ****************************** */

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
			    int encryptValue, char *userQuestion) {
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

  if(return_data.dptr == NULL) {
    char *thePw, pw1[16], pw2[16];
    /* If not existing, then add user 'admin' and ask for password  */

    if(userQuestion != NULL) {
      if(myGlobals.runningPref.daemonMode) {
	/*
	 * We need a password for the admin user, but the user requested
	 * daemon mode.  stdin is already detached; getpass() would fail.
	 *
	 * Courtesy of Ambrose Li <a.c.li@ieee.org>
	 *
	 */
	traceEvent(CONST_TRACE_FATALERROR,
		   "No password for admin user - please re-run ntop in non-daemon mode first");
	exit(1); /* Just in case */
      }

      memset(pw1, 0, sizeof(pw1)); memset(pw2, 0, sizeof(pw2));

      while(pw1[0] == '\0') {
        thePw = getpass(userQuestion);
#ifdef WIN32
        if( (isWinNT()) || (strlen(thePw) >= 5) ) {
#else
        if(strlen(thePw) >= 5) {
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
  } else
    free(return_data.dptr);
}

/* ****************************** */

void setAdminPassword(char* pass) {
  traceEvent(CONST_TRACE_INFO, "Setting administrator password...");
  
  if(pass == NULL)
    addKeyIfMissing("1admin", NULL, 1, CONST_ADMINPW_QUESTION);
  else
    addKeyIfMissing("1admin", pass, 1, NULL);

  traceEvent(CONST_TRACE_INFO, "Admin password set...");
}

/* ****************************** */

void addDefaultAdminUser(void) {
  /* Add user 'admin' and ask for password if not existing */
  addKeyIfMissing("1admin", NULL, 1, CONST_ADMINPW_QUESTION);

  /* Add user 'admin' for URL 'show...' if not existing */
  addKeyIfMissing("2showU",      "users=1admin", 0, NULL);
  addKeyIfMissing("2modifyU",    "users=1admin", 0, NULL);
  addKeyIfMissing("2deleteU",    "users=1admin", 0, NULL);
  addKeyIfMissing("2shut",       "users=1admin", 0, NULL);
  addKeyIfMissing("2resetStats", "users=1admin", 0, NULL);
  addKeyIfMissing("2chang",      "users=1admin", 0, NULL);
  addKeyIfMissing("2configNtop", "users=1admin", 0, NULL);
  addKeyIfMissing("2privacyFlag","users=1admin", 0, NULL);
  addKeyIfMissing("2"CONST_EDIT_PREFS,"users=1admin", 0, NULL);
  addKeyIfMissing("2"CONST_PURGE_HOST,"users=1admin", 0, NULL);
}

/* ************************************ */

#define NTOP_SAVE_PREFS     "SP"
#define NTOP_RESTORE_DEF    "RD"
#define CONFIG_STR_ENTRY(bg,title,name,size,configvalue,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s</td><td align=left><INPUT NAME=\"%s\" SIZE=%d VALUE=\"%s\"><BR>%s</td></TR>\n", bg, title, name, size, (configvalue != NULL) ? configvalue : "", descr); \
        sendString (buf);

#define CONFIG_FILE_ENTRY(bg,title,name,size,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td align=left><INPUT NAME=%s SIZE=%d VALUE=%s TYPE=FILE><BR>%s</TD></TR>\n", bg, title, name, size, (value != NULL) ? value : "(null)", descr); \
        sendString (buf);

#define CONFIG_INT_ENTRY(bg,title,name,size,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td align=left><INPUT NAME=%s SIZE=%d VALUE=%d><BR>%s</TD></TR>\n", bg, title, name, size, value, descr); \
        sendString (buf);

#define CONFIG_CHKBOX_ENTRY(bg,title,name,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td align=left><INPUT TYPE=checkbox NAME=%s VALUE=%d %s><BR>%s</TD></TR>\n", bg, title, name, value, value ? "CHECKED" : "", descr); \
        sendString (buf);

#define CONFIG_RADIO_ENTRY(bg,title,name,value,descr) \
        safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf), "<tr><td align=left %s>%s<td align=left><INPUT TYPE=radio NAME=%s VALUE=1 %s>Yes<INPUT TYPE=radio NAME=%s VALUE=0 %s>No<br>%s</TD></TR>\n", bg, title, name, value ? "CHECKED" : "", name, !value ? "CHECKED" : "", descr); \
        sendString (buf);

#define CONFIG_RADIO_OPTION(title,name,value,checked) \
        safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<INPUT TYPE=radio NAME=%s VALUE=%d %s>%s<BR>\n", name, value, (checked) ? "CHECKED" : "", title); \
        sendString(buf);


/* ************************************************* */

 int processNtopConfigData (char *buf, int savePref) {
   char *strtokState, *mainState;
   int startCap = FALSE, action;
   UserPref tmpPrefs;
   char *devices = NULL, *foundDevices = NULL, *token;
   char basic_prefs = 0, display_prefs = 0, ip_prefs = 0, 
     advanced_prefs = 0, debug_prefs = 0;

   /* traceEvent(CONST_TRACE_INFO, "RRD: buf='%s'", buf); */

   token = strtok_r(buf, "&", &mainState);
   tmpPrefs = myGlobals.savedPref;

   /* however, switch off all chkbox fields. If they've been set, they'll get
    * processed. If they stay turned off, it is a sign that they've been
    * unchecked and we need to handle this.
    */
   tmpPrefs.enableSessionHandling = tmpPrefs.enablePacketDecoding = 0;
   tmpPrefs.stickyHosts = tmpPrefs.trackOnlyLocalHosts = 0;
   tmpPrefs.disablePromiscuousMode = tmpPrefs.disableMutexExtraInfo = 0;
   tmpPrefs.disableStopcap = 0;
   tmpPrefs.debugMode = tmpPrefs.daemonMode = tmpPrefs.w3c = 0;
   tmpPrefs.numericFlag = dnsResolutionForAll;
   tmpPrefs.mergeInterfaces = tmpPrefs.enableL7 = 0;
   tmpPrefs.enableSuspiciousPacketDump = 0;
   tmpPrefs.enableSessionHandling = 0;

   devices = tmpPrefs.devices;
   tmpPrefs.devices = NULL;

   while(token != NULL) {
     char *key, *value, value_buf[2048];

     key = strtok_r(token, "=", &strtokState);
     if(key != NULL) value = strtok_r(NULL, "=", &strtokState); else value = NULL;

	 if(value != NULL) {
	  safe_snprintf (__FILE__, __LINE__, value_buf, sizeof(value_buf),
					 "%s", value);
  	  unescape_url(value_buf);
      value = value_buf;
	 }

     if(key) {
       action = processNtopPref(key, value, savePref, &tmpPrefs);

       if(action) {
	 startCap = TRUE;
       }

       if(!strcmp(key, "BASIC_PREFS")) basic_prefs = 1;
       else if(!strcmp(key, "DISPLAY_PREFS")) display_prefs = 1;
       else if(!strcmp(key, "IP_PREFS")) ip_prefs = 1;
       else if(!strcmp(key, "ADVANCED_PREFS")) advanced_prefs = 1;
       else if(!strcmp(key, "DEBUG_PREFS")) debug_prefs = 1;

       if(!strcmp(key, NTOP_PREF_DEVICES))
	 foundDevices = value;
     }

     token = strtok_r(NULL, "&", &mainState);
   }

   if((!foundDevices) && basic_prefs) {
     delPrefsValue(NTOP_PREF_DEVICES);
     if(tmpPrefs.devices) free(tmpPrefs.devices);
     tmpPrefs.devices = NULL;
   }

   if(devices) {
     free(devices);
   }

   /* Now we need to delete all the preferences that were unchecked.
    * Radio box & checkbox preferences that were set in a previous instance
    * but cleared in this instance will not appear in the POST data. So, if
    * the value has changed from what existed before, we need to remove them
    * from the saved preferences file.
    */

     if(basic_prefs && myGlobals.savedPref.enableSessionHandling &&
	 !tmpPrefs.enableSessionHandling) {
       /* default for enableSessionHandling is TRUE */
       processNtopPref(NTOP_PREF_EN_SESSION, FALSE, savePref, &tmpPrefs);
     }

     if(basic_prefs && myGlobals.savedPref.enablePacketDecoding &&
	 !tmpPrefs.enablePacketDecoding) {
       processNtopPref(NTOP_PREF_EN_PROTO_DECODE, FALSE, savePref, &tmpPrefs);
     }

     if(basic_prefs && myGlobals.savedPref.stickyHosts && !tmpPrefs.stickyHosts) {
       processNtopPref(NTOP_PREF_STICKY_HOSTS, FALSE, savePref, &tmpPrefs);
     }

     if(basic_prefs && myGlobals.savedPref.trackOnlyLocalHosts &&
	 !tmpPrefs.trackOnlyLocalHosts) {
       processNtopPref(NTOP_PREF_TRACK_LOCAL, FALSE, savePref, &tmpPrefs);
     }

     if(basic_prefs && myGlobals.savedPref.disablePromiscuousMode &&
	 !tmpPrefs.disablePromiscuousMode) {
       processNtopPref(NTOP_PREF_NO_PROMISC, FALSE, savePref, &tmpPrefs);
     }

     if(basic_prefs && myGlobals.savedPref.daemonMode && !tmpPrefs.daemonMode) {
       processNtopPref(NTOP_PREF_DAEMON, FALSE, savePref, &tmpPrefs);
     }

   if(display_prefs && myGlobals.savedPref.w3c && !tmpPrefs.w3c) {
     processNtopPref(NTOP_PREF_W3C, FALSE, savePref, &tmpPrefs);
   }

   if(ip_prefs && myGlobals.savedPref.numericFlag && !tmpPrefs.numericFlag) {
     processNtopPref(NTOP_PREF_NUMERIC_IP, FALSE, savePref, &tmpPrefs);
   }

   if(advanced_prefs && myGlobals.savedPref.mergeInterfaces && !tmpPrefs.mergeInterfaces) {
     processNtopPref(NTOP_PREF_MERGEIF, FALSE, savePref, &tmpPrefs);
   }

   if(advanced_prefs && myGlobals.savedPref.enableL7 && !tmpPrefs.enableL7) {
     processNtopPref(NTOP_PREF_ENABLE_L7PROTO, FALSE, savePref, &tmpPrefs);
   }

   if(debug_prefs && myGlobals.savedPref.debugMode && !tmpPrefs.debugMode) {
     processNtopPref(NTOP_PREF_DBG_MODE, FALSE, savePref, &tmpPrefs);
   }

   if(debug_prefs && myGlobals.savedPref.enableSuspiciousPacketDump &&
       !tmpPrefs.enableSuspiciousPacketDump) {
     processNtopPref(NTOP_PREF_DUMP_SUSP, FALSE, savePref, &tmpPrefs);
   }

   if(debug_prefs && myGlobals.savedPref.disableMutexExtraInfo &&
       !tmpPrefs.disableMutexExtraInfo) {
     processNtopPref(NTOP_PREF_NO_MUTEX_EXTRA, FALSE, savePref, &tmpPrefs);
   }

   /* Copy over the preferences now */
   myGlobals.savedPref = tmpPrefs;

   /* Handle immediates */
   myGlobals.runningPref.traceLevel = myGlobals.savedPref.traceLevel;

   return (startCap);
 }

/* ************************************************* */

void printNtopConfigHeader (char *url, UserPrefDisplayPage configScr)
{
  char buf[1024];
  char theLink[32];

  safe_snprintf (__FILE__, __LINE__, theLink, sizeof(theLink),
		 "/configNtop.html?&showD=");

  switch (configScr) {
  case showPrefBasicPref:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
		  "[ <B>Basic Prefs</B> ]&nbsp;"
		  "[ <A HREF=%s2>Display Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s3>IP Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s4>FC Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s5>Advanced Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s6>Debugging Prefs</A> ]&nbsp;"
		  "</p>",
		  theLink, theLink, theLink, theLink, theLink, theLink
		  );
    break;

  case showPrefDisplayPref:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
		  "[ <A HREF=%s1>Basic Prefs</A> ]&nbsp;"
		  "[ <B>Display Prefs</B> ]&nbsp;"
		  "[ <A HREF=%s3>IP Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s4>FC Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s5>Advanced Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s6>Debugging Prefs</A> ]&nbsp;"
		  "</p>",
		  theLink, theLink, theLink, theLink, theLink, theLink
		  );
    break;

  case showPrefIPPref:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
		  "[ <A HREF=%s1>Basic Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s2>Display Prefs</A> ]&nbsp;"
		  "[ <B>IP Prefs</B> ]&nbsp;"
		  "[ <A HREF=%s4>FC Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s5>Advanced Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s6>Debugging Prefs</A> ]&nbsp;"
		  "</p>",
		  theLink, theLink, theLink, theLink, theLink, theLink);
    break;

  case showPrefAdvPref:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
		  "[ <A HREF=%s1>Basic Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s2>Display Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s3>IP Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s4>FC Prefs</A> ]&nbsp;"
		  "[ <B>Advanced Prefs</B> ]&nbsp;"
		  "[ <A HREF=%s6>Debugging Prefs</A> ]&nbsp;"
		  "</p>",
		  theLink, theLink, theLink, theLink, theLink, theLink);
    break;

  case showPrefDbgPref:
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<P ALIGN=CENTER>"
		  "[ <A HREF=%s1>Basic Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s2>Display Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s3>IP Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s4>FC Prefs</A> ]&nbsp;"
		  "[ <A HREF=%s5>Advanced Prefs</A> ]&nbsp;"
		  "[ <B>Debugging Prefs</B> ]&nbsp;"
		  "</p>",
		  theLink, theLink, theLink, theLink, theLink, theLink);
    break;
  }

  sendString (buf);

  safe_snprintf (__FILE__, __LINE__, buf, sizeof (buf),
		 "<FORM ACTION=%s%d method=POST>"
		 " <TABLE BORDER=1 "TABLE_DEFAULTS">\n"
		 "<TR><TH ALIGN=CENTER "DARK_BG">Preference</TH>"
		 "<TH ALIGN=CENTER "DARK_BG">Configured Value</TH></TR>\n",
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
    if(*u.p == ch)
      save = u.p;
    if(*u.p == '\0')
      return(save);
  }
  /* NOTREACHED */
}
#endif

/* ***************************************************** */

void handleNtopConfig(char* url, UserPrefDisplayPage configScr,
		      int postLen) {
  char buf[4096], token_buf[512], hostStr[MAXHOSTNAMELEN+16];
  bool startCap = FALSE;
  int len;
  UserPref defaults, *pref = &myGlobals.savedPref;

  /*
   * Configuration is dealt with via POST method. So read the data first.
   */
  if(postLen) {
    if((len = readHTTPpostData (postLen, buf, 1024)) != postLen) {
      traceEvent (CONST_TRACE_WARNING, "handleNtopConfig: Unable to retrieve "
		  "all POST data (%d, expecting %d). Aborting processing\n",
		  len, postLen);
    } else {
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

	/* traceEvent (CONST_TRACE_INFO, "BUF='%s'\n", buf); */

	/* locate the last parameter which tells us which button got pressed */
	if((token = rindex (buf, '&')) != NULL) {
	  token++;
      safe_snprintf(__FILE__, __LINE__, token_buf, sizeof(token_buf),
					"%s", token);
  	  unescape_url(token_buf);
	  token = token_buf;

	  if(strncmp (token, NTOP_SAVE_PREFS,
		       strlen (NTOP_SAVE_PREFS)) == 0) {
	    savePref = TRUE;
	  } else if(strncmp (token, NTOP_RESTORE_DEF,
			    strlen (NTOP_RESTORE_DEF)) == 0) {
	    restoreDef = TRUE;
	  }
	}

	if(restoreDef) {
	  initUserPrefs (&defaults);
          defaults.samplingRate =  myGlobals.savedPref.samplingRate;
	  pref = &defaults;
	} else {
	  /* process preferences and start capture if necessary */
	  processNtopConfigData (buf, savePref);
	  if(startCap) {
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
  printHTMLheader("Configure ntop", NULL, 0);

  sendString ("<CENTER>\n");

  printNtopConfigHeader(url, configScr);

  switch (configScr) {
  case showPrefBasicPref:
    {
      pcap_if_t *devpointer = myGlobals.allDevs;
      int i;

      sendString("<TR><INPUT TYPE=HIDDEN NAME=BASIC_PREFS VALUE=1>"
		 "<TD ALIGN=LEFT "DARK_BG">Capture Interfaces (-i)</TD><TD ALIGN=LEFT>\n");

      if(devpointer != NULL) {
	for (i = 0; devpointer != 0; i++) {
	  if(strcmp(devpointer->name, "any")) {
	    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf),
			  "<INPUT TYPE=checkbox NAME=\"%s\" VALUE=\"%s\" %s>%s<br>\n",
			  NTOP_PREF_DEVICES, devpointer->name,
			  (pref->devices && strstr(pref->devices, devpointer->name)) ? "CHECKED" : "",
			  devpointer->description ? devpointer->description : devpointer->name);
	    sendString(buf);
	  }

	  devpointer = devpointer->next;
	}
      } else {
	sendString("<INPUT TYPE=hidden name=\""NTOP_PREF_DEVICES"\" value=\"\">");
#ifndef WIN32
	sendString("<font color=red>You cannot set the capture interface: missing privileges.</font><br>"
		   "You need to start ntop with super-user privileges [-u]");
#endif
      }
      sendString("</TD></TR>\n");
    }

  default:
    CONFIG_STR_ENTRY(DARK_BG, "Capture Filter Expression (-B)",
		     NTOP_PREF_FILTER,
		     50, pref->currentFilterExpression,
		     "Restrict the traffic seen by ntop. BPF syntax.");

    CONFIG_INT_ENTRY(DARK_BG, "Packet sampling rate (-C)", NTOP_PREF_SAMPLING,
		     50, pref->samplingRate, "Sampling rate [1 = no sampling]");

    if(pref->webAddr == NULL) {
      safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
		     "%d", pref->webPort);
    } else {
      safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
		     "%s:%d", pref->webAddr, pref->webPort);
    }
    CONFIG_STR_ENTRY(DARK_BG, "HTTP Server (-w)", NTOP_PREF_WEBPORT,
		     50, hostStr,
		     "HTTP Server [Address:]Port of ntop's web interface");

#ifdef HAVE_OPENSSL
    if(pref->sslAddr == NULL) {
      safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
		     "%d", pref->sslPort);
    } else {
      safe_snprintf (__FILE__, __LINE__, hostStr, sizeof (hostStr),
		     "%s:%d", pref->sslAddr, pref->sslPort);
    }
    CONFIG_STR_ENTRY(DARK_BG, "HTTPS Server (-W)", NTOP_PREF_SSLPORT, 50,
		     hostStr, "HTTPS Server [Address:]Port of ntop's web "
		     "interface");
#endif

    CONFIG_RADIO_ENTRY(DARK_BG, "Enable Session Handling (-z)",
		       NTOP_PREF_EN_SESSION,
		       pref->enableSessionHandling, "");

    CONFIG_RADIO_ENTRY(DARK_BG, "Enable Protocol Decoders (-b)",
		       NTOP_PREF_EN_PROTO_DECODE,
		       pref->enablePacketDecoding, "");

    CONFIG_STR_ENTRY(DARK_BG, "Flow Spec (-F)", NTOP_PREF_FLOWSPECS, 50,
		     pref->flowSpecs,
		     "Flow is a stream of captured packets that match a specified rule");

    CONFIG_STR_ENTRY(DARK_BG, "Local Subnet Address (-m)",
		     NTOP_PREF_LOCALADDR, 50,
		     pref->localAddresses,
		     "Local subnets in ntop reports (use , to separate them). Mandatory for packet capture files");

    CONFIG_STR_ENTRY(DARK_BG, "Known Subnet Address (-m)",
		     NTOP_PREF_KNOWNSUBNETS, 50,
		     pref->knownSubnets,
		     "Known subnets in ntop reports (use , to separate them). Mandatory for packet capture files");

    CONFIG_RADIO_ENTRY(DARK_BG, "Sticky Hosts (-c)",
		       NTOP_PREF_STICKY_HOSTS, pref->stickyHosts,
		       "Don't purge idle hosts from memory");

    CONFIG_RADIO_ENTRY(DARK_BG, "Track Local Hosts (-g)",
		       NTOP_PREF_TRACK_LOCAL,
		       pref->trackOnlyLocalHosts,
		       "Capture data only about local hosts");

    CONFIG_RADIO_ENTRY(DARK_BG, "Disable Promiscuous Mode (-s)",
		       NTOP_PREF_NO_PROMISC,
		       pref->disablePromiscuousMode,
		       "Don't set the interface(s) into promiscuous mode");

    CONFIG_RADIO_ENTRY(DARK_BG, "Run as daemon (-d)", NTOP_PREF_DAEMON,
		       pref->daemonMode, "Run Ntop as a daemon");
    break;

  case showPrefDisplayPref:
    sendString("<INPUT TYPE=HIDDEN NAME=DISPLAY_PREFS VALUE=1>");

    CONFIG_INT_ENTRY(DARK_BG, "Refresh Time (-r)", NTOP_PREF_REFRESH_RATE,
		     5, pref->refreshRate,
		     "Delay (in secs) between automatic screen updates for "
		     "supported HTML pages");

    CONFIG_INT_ENTRY(DARK_BG, "Max Table Rows (-e)", NTOP_PREF_MAXLINES, 5,
		     pref->maxNumLines,
		     "Max number of lines that ntop will display on each "
		     " generated HTML page");

    CONFIG_RADIO_ENTRY(DARK_BG, "Use W3C", NTOP_PREF_W3C,
		       pref->w3c,
		       "Generate 'BETTER' (but not perfect) w3c "
		       "compliant html 4.01 output");
    break;

  case showPrefIPPref:
    sendString("<INPUT TYPE=HIDDEN NAME=IP_PREFS VALUE=1>");

    sendString("<TR><TD ALIGN=LEFT "DARK_BG">Use IPv4 or IPv6 (-4/-6)</TD><TD ALIGN=LEFT>\n");
    CONFIG_RADIO_OPTION("v4",   NTOP_PREF_IPV4V6, NTOP_PREF_VALUE_AF_INET,  pref->ipv4or6 == AF_INET);
    CONFIG_RADIO_OPTION("v6",   NTOP_PREF_IPV4V6, NTOP_PREF_VALUE_AF_INET6, pref->ipv4or6 == AF_INET6);
    CONFIG_RADIO_OPTION("Both", NTOP_PREF_IPV4V6, NTOP_PREF_VALUE_AF_BOTH,  pref->ipv4or6 == AF_UNSPEC);
    sendString("</TD></TR>\n");

    CONFIG_STR_ENTRY(DARK_BG, "Local Domain Name (-D)",
		     NTOP_PREF_DOMAINNAME, 10, pref->domainName,
		     "Only if ntop is having difficulty determining it "
		     "from the interface or in case of capture files");

    sendString("<TR><TD ALIGN=LEFT "DARK_BG">DNS resolution mode (-n)</TD><TD ALIGN=LEFT>\n");
    CONFIG_RADIO_OPTION("None",		     NTOP_PREF_NUMERIC_IP, noDnsResolution, 		    pref->numericFlag == noDnsResolution);
    CONFIG_RADIO_OPTION("Local Only",	     NTOP_PREF_NUMERIC_IP, dnsResolutionForLocalHostsOnly,  pref->numericFlag == dnsResolutionForLocalHostsOnly);
    CONFIG_RADIO_OPTION("Local/Remote Only", NTOP_PREF_NUMERIC_IP, dnsResolutionForLocalRemoteOnly, pref->numericFlag == dnsResolutionForLocalRemoteOnly);
    CONFIG_RADIO_OPTION("All",		     NTOP_PREF_NUMERIC_IP, dnsResolutionForAll,		    pref->numericFlag == dnsResolutionForAll);
    sendString("</TD></TR>\n");

    CONFIG_STR_ENTRY(DARK_BG, "TCP/UDP Protocols To Monitor (-p)",
		     NTOP_PREF_PROTOSPECS, 50, pref->protoSpecs,
		     "format is &lt;label&gt;=&lt;protocol list&gt; [, &lt;"
		     "label&gt;=&lt;protocol list&gt;] OR a filename"
		     "of a file containing such a format");
    CONFIG_STR_ENTRY(DARK_BG, "P3P-CP", NTOP_PREF_P3PCP, 50,
		     pref->P3Pcp,
		     "Return value for p3p compact policy header");

    CONFIG_STR_ENTRY(DARK_BG, "P3P-URI", NTOP_PREF_P3PURI, 50,
		     pref->P3Puri,
		     "Return value for p3p policyref header");

    break;

  case showPrefAdvPref:
    sendString("<INPUT TYPE=HIDDEN NAME=ADVANCED_PREFS VALUE=1>");

    CONFIG_INT_ENTRY(DARK_BG, "Max Hashes (-x)", NTOP_PREF_MAXHASH, 5,
		     pref->maxNumHashEntries,
		     "Limit number of host hash entries created in order"
		     " to limit memory used by ntop");

    CONFIG_INT_ENTRY(DARK_BG, "Max Sessions (-X)", NTOP_PREF_MAXSESSIONS, 5,
		     pref->maxNumSessions,
		     "Limit number of IP sessions entries created in order"
		     " to limit memory used by ntop");

    CONFIG_RADIO_ENTRY(DARK_BG, "Merge Interfaces (-M)",
		       NTOP_PREF_MERGEIF, pref->mergeInterfaces,
		       "Yes = merge data from all interfaces (if possible), No = do not merge data from all interfaces");

    CONFIG_STR_ENTRY(DARK_BG, "Pcap Log Base Path (-O)",
		     NTOP_PREF_PCAP_LOGBASE, 50, pref->pcapLogBasePath,
		     "Directory where packet dump files are created");
    break;

  case showPrefDbgPref:
    sendString("<INPUT TYPE=HIDDEN NAME=DEBUG_PREFS VALUE=1>");

    CONFIG_RADIO_ENTRY(DARK_BG, "Run in debug mode (-K)",
		       NTOP_PREF_DBG_MODE, pref->debugMode,
		       "Simplifies debugging Ntop");

    CONFIG_INT_ENTRY(DARK_BG, "Trace Level (-t)<br><i>&nbsp;&nbsp;&nbsp;(takes effect immediately)</i>", NTOP_PREF_TRACE_LVL, 5,
		     pref->traceLevel,
		     "Level of detailed messages ntop will display");

    CONFIG_RADIO_ENTRY(DARK_BG, "Save Suspicious Packets (-q)",
		       NTOP_PREF_DUMP_SUSP,
		       pref->enableSuspiciousPacketDump,
		       "Create a dump file (pcap) of suspicious packets");

    CONFIG_STR_ENTRY(DARK_BG, "Log HTTP Requests (-a)",
		     NTOP_PREF_ACCESS_LOG, 50, pref->accessLogFile,
		     "Request HTTP logging and specify the location of the "
		     "log file");

#ifndef WIN32
    CONFIG_INT_ENTRY(DARK_BG, "Use Syslog (-L)", NTOP_PREF_USE_SYSLOG, 5,
		     pref->useSyslog,
		     "Send log messages to the system log instead of stdout");
#endif

    CONFIG_STR_ENTRY(DARK_BG, "Write captured frames to (-l)",
		     NTOP_PREF_PCAP_LOG, 50, pref->pcapLog,
		     "Causes a dump file to be created of the captured by "
		     "ntop in libpcap format");

    CONFIG_RADIO_ENTRY(DARK_BG, "Disable Extra Mutex Info",
		       NTOP_PREF_NO_MUTEX_EXTRA,
		       pref->disableMutexExtraInfo,
		       "Disables storing of extra information about the locks"
		       " and unlocks of the protective mutexes Ntop uses");
    break;
  }

  sendString ("</TABLE>");
  /* Save Prefs */
  if(configScr == showPrefDisplayPref) {
    sendString("<tr><td colspan=\"2\" align=\"center\">&nbsp;<p>"
	       "<input type=submit name=" NTOP_SAVE_PREFS " value=\"Save&nbsp;Prefs\">&nbsp;"
	       "<input type=submit name=AP value=\"Apply&nbsp;Prefs\">&nbsp;"
	       "<input type=submit name=" NTOP_RESTORE_DEF " value=\"Restore&nbsp;Defaults\">"
	       "</td></tr></table>\n"
	       "</form>\n<p></center>\n");
  } else {
    sendString("<tr><td colspan=\"2\" align=\"center\">&nbsp;<p>"
	       "<input type=submit name=" NTOP_SAVE_PREFS " value=\"Save&nbsp;Prefs\">&nbsp;"
	       "<input type=submit name=" NTOP_RESTORE_DEF " value=\"Restore&nbsp;Defaults\">"
	       "</td></tr></table>\n"
	       "</form>\n<p></center>\n");
  }

  sendString ("<P Align=CENTER><FONT COLOR = \"FF00FF\">Except as indicated, settings take effect at next startup</FONT></CENTER><P>");
  sendString ("<P Align=CENTER><FONT COLOR = \"FF00FF\">See <a href = \"info.html\">Show Configuration</A>"
	      " for runtime values</FONT></CENTER><P>");

  printHTMLtrailer();
}
