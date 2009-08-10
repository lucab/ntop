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

#ifdef HAVE_LUA

static HostTraffic *ntop_host = NULL;
static char query_string[2048];

/* *********************************************************** */

static int ntop_lua_check(lua_State* vm, char* func,
			  int pos, int expected_type) {
  if(lua_type(vm, pos) != expected_type) {
    traceEvent(CONST_TRACE_ERROR,
	       "%s : expected %s, got %s", func,
	       lua_typename(vm, expected_type),
	       lua_typename(vm, lua_type(vm,pos)));
    return(-1);
  }

  return(0);
}

/* *********************************************************** */

static int ntop_lua_sendString(lua_State* vm) {
  char *str;

  if(ntop_lua_check(vm, "ntop_lua_sendString", 1, LUA_TSTRING)) return(0);
  str = (char*)(char*)lua_tostring(vm,1);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "ntop_lua_sendString(%s)", str);
#endif

  if(str && (strlen(str) > 0)) sendString(str);
  return(1);
}

/* *********************************************************** */

/* int mime_type, char *title */
static int ntop_lua_send_http_header(lua_State* vm) {
  int mime_type;
  char *title;

  if(ntop_lua_check(vm, "ntop_lua_send_http_header", 1, LUA_TNUMBER)) return(0);
  mime_type = (int)lua_tonumber(vm, 1);

  if(ntop_lua_check(vm, "ntop_lua_send_http_header", 2, LUA_TSTRING)) return(0);
  title = (char*)lua_tostring(vm, 2);

  sendHTTPHeader(mime_type /* FLAG_HTTP_TYPE_HTML */, 0, 0);
  if(title && (strlen(title) > 0)) printHTMLheader(title, NULL, 0);
  return(1);
}

/* *********************************************************** */

static int ntop_lua_send_html_footer(lua_State* vm) {
  printHTMLtrailer();
  return(1);
}

/* *********************************************************** */

/* char* fileName */
static int ntop_lua_sendFile(lua_State* vm) {
  char *fileName;

  if(ntop_lua_check(vm, "ntop_lua_sendFile", 1, LUA_TSTRING)) return(0);
  fileName = (char*)(char*)lua_tostring(vm,1);

  sendFile(fileName, 1);
  return(1);
}

/* *********************************************************** */

static int ntop_lua_getFirstHost(lua_State* vm) {
  int actualDeviceId;

  if(ntop_lua_check(vm, "ntop_lua_getFirstHost", 1, LUA_TNUMBER)) return(0);
  actualDeviceId = (int)lua_tonumber(vm, 1);

  ntop_host = getFirstHost(actualDeviceId);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "[lua] getFirstHost(%d)=%p",
	     actualDeviceId, ntop_host);
#endif

  return(1);
}

/* *********************************************************** */

static int ntop_lua_getNextHost(lua_State* vm) {
 int actualDeviceId;

  if(ntop_lua_check(vm, "ntop_lua_getNextHost", 1, LUA_TNUMBER)) return(0);
  actualDeviceId = (int)lua_tonumber(vm, 1);

  if(ntop_host == NULL) {
    ntop_host = getFirstHost(actualDeviceId);
  } else {
    ntop_host = getNextHost(actualDeviceId, ntop_host);
  }

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "[lua] getNextHost()=%p", ntop_host);
#endif

  return(ntop_host ? 1 : -1);
}

/* *********************************************************** */

static int ntop_lua_getQueryString(lua_State* vm) {
  lua_pushfstring(vm, "%s", query_string);
  return(1);
}

/* *********************************************************** */

static int ntop_lua_host_ethAddress(lua_State* vm) {
  if(lua_type(vm, 1) !=  LUA_TNONE) /* A value has been passed */ {
    /* SET */
    char *str;

    if(ntop_lua_check(vm, "ntop_lua_host_ethAddress", 1, LUA_TSTRING)) return(0);
    str = (char*)(char*)lua_tostring(vm,1);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "ntop_lua_ethAddress(%s)", str ? str : "NULL");
#endif
    snprintf(ntop_host->ethAddressString, sizeof(ntop_host->ethAddressString), "%s", str);
  } else {
    /* GET */
    lua_pushfstring(vm, "%s", (ntop_host != NULL) ? ntop_host->ethAddressString : "");
  }

  return(1);
}

static int ntop_lua_host_ipAddress(lua_State* vm) {
  if(lua_type(vm, 1) !=  LUA_TNONE) /* A value has been passed */ {
    /* SET */
    char *str;

    if(ntop_lua_check(vm, "ntop_lua_host_ipAddress", 1, LUA_TSTRING)) return(0);
    str = (char*)(char*)lua_tostring(vm,1);
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "ntop_lua_host_ipAddress(%s)", str ? str : "NULL");
#endif
    snprintf(ntop_host->hostNumIpAddress, sizeof(ntop_host->hostNumIpAddress), "%s", str);
  } else {
    /* GET */
    lua_pushfstring(vm, "%s", (ntop_host != NULL) ? ntop_host->hostNumIpAddress : "");
  }
  return(1);
}

static int ntop_lua_host_hostResolvedName(lua_State* vm) {
  lua_pushfstring(vm, "%s", (ntop_host != NULL) ? ntop_host->hostResolvedName : "");
  return(1);
}

static int ntop_lua_host_vlanId(lua_State* vm) {
  lua_Integer i = (ntop_host != NULL) ? ntop_host->vlanId : -1;
  lua_pushinteger(vm, i);
  return(1);
}

static int ntop_lua_host_hostAS(lua_State* vm) {
  lua_Integer i = (ntop_host != NULL) ? ntop_host->hostAS : -1;
  lua_pushinteger(vm, i);
  return(1);
}

static int ntop_lua_host_pktSent(lua_State* vm) {
  lua_Integer i = (ntop_host != NULL) ? ntop_host->pktSent.value : -1;
  lua_pushinteger(vm, i);
  return(1);
}

static int ntop_lua_host_pktRcvd(lua_State* vm) {
  lua_Integer i = (ntop_host != NULL) ? ntop_host->pktRcvd.value : -1;
  lua_pushinteger(vm, i);
  return(1);
}

static int ntop_lua_host_bytesSent(lua_State* vm) {
  lua_Integer i = (ntop_host != NULL) ? ntop_host->bytesSent.value : -1;
  lua_pushinteger(vm, i);
  return(1);
}

static int ntop_lua_host_bytesRcvd(lua_State* vm) {
  lua_Integer i = (ntop_host != NULL) ? ntop_host->bytesRcvd.value : -1;
  lua_pushinteger(vm, i);
  return(1);
}

/* *********************************************************** */

/* ntop object methods */
static luaL_reg ntop_reg[] = {
  { "sendString",       ntop_lua_sendString },
  { "send_http_header", ntop_lua_send_http_header },
  { "send_html_footer", ntop_lua_send_html_footer },
  { "sendFile",         ntop_lua_sendFile },
  { "getFirstHost",     ntop_lua_getFirstHost },
  { "getNextHost",      ntop_lua_getNextHost },
  { "getQueryString",   ntop_lua_getQueryString },
  {NULL,                NULL}
};

/* ntop host object methods */
static luaL_reg ntop_host_reg[] = {
  { "ethAddress",       ntop_lua_host_ethAddress },
  { "ipAddress",        ntop_lua_host_ipAddress },
  { "hostResolvedName", ntop_lua_host_hostResolvedName },
  { "vlanId",    ntop_lua_host_vlanId },
  { "hostAS",    ntop_lua_host_hostAS },
  { "pktSent",   ntop_lua_host_pktSent },
  { "pktRcvd",   ntop_lua_host_pktRcvd },
  { "bytesSent", ntop_lua_host_bytesSent },
  { "bytesRcvd", ntop_lua_host_bytesRcvd },
  {NULL,       NULL}
};

static void register_host_class( lua_State *L, char *class_name, luaL_reg *class_methods)
{
  luaL_newmetatable( L, class_name );
  lua_pushstring( L, "__index" );
  lua_pushvalue( L, -2 );         // pushes the metatable
  lua_settable( L, -3 );          // metatable.__index = metatable
  luaL_register( L, class_name, class_methods );
}

static int ntop_register(lua_State *L) {
  luaL_register(L, "ntop", ntop_reg);
  register_host_class(L, "host", ntop_host_reg);
  return 0;
}

/* *********************************************************** */

/* http://localhost:3000/lua/test.lua */

int handleLuaHTTPRequest(char *url) {
  int idx, found = 0;
  char lua_path[256];
  struct stat statbuf;
  lua_State* L;
  char *question_mark = strchr(url, '?');

  traceEvent(CONST_TRACE_INFO, "Calling lua... [%s]", url);

  if(question_mark) question_mark[0] = '\0';
  safe_snprintf(__FILE__, __LINE__, query_string, sizeof(query_string)-1, "%s", question_mark ? &question_mark[1] : "");

  for(idx=0; (!found) && (myGlobals.dataFileDirs[idx] != NULL); idx++) {
  safe_snprintf(__FILE__, __LINE__, lua_path, sizeof(lua_path),
	  "%s/lua/%s", myGlobals.dataFileDirs[idx], url);
    revertSlashIfWIN32(lua_path, 0);

    if(!stat(lua_path, &statbuf)) {
      /* Found */
      /* traceEvent(CONST_TRACE_INFO, "[lua] [%d] Found %s", idx, lua_path); */
      found = 1;
      break;
    } else {
      /* traceEvent(CONST_TRACE_INFO, "[lua] [%d] Not found %s", idx, lua_path); */
    }
  }

  if(!found) {
    returnHTTPpageNotFound(NULL);
    return(1);
  }

  /* *********************** */

  L = lua_open();
  luaL_openlibs(L);

  /* Load ntop extensions */
  ntop_register(L);

  if(luaL_dofile(L, lua_path) == 1) {
    traceEvent(CONST_TRACE_ERROR, "[lua] Error while executing file %s: %s",
	       lua_path, lua_tostring(L, -1));
    sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
    printHTMLheader("Lua Runtime Error", NULL, BITFLAG_HTML_NO_REFRESH);
    printFlagedWarning((char*)lua_tostring(L, -1));
  }

  lua_close(L);

  return(1);
}


#endif /* HAVE_LUA */
