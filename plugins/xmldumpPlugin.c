/*
 *  Copyright (C) 2003-2004 Burton M. Strausss III <burton@ntopsupport.com>
 *                          Luca Deri <deri@ntop.org>
 *
 *  			    http://www.ntop.org/
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

/* XMLDUMP_DEBUG causes xmldump.c to output debug information. */
/* #define XMLDUMP_DEBUG */

#include "ntop.h"
#include "globals-report.h"
#include <stdarg.h>
#include <setjmp.h>

#ifdef MAKE_WITH_XMLDUMP
#include <glibconfig.h>
#warning
#warning ===========================================================
#warning
#warning The include of gdome.h that follows will generate a lot of
#warning compile warnings about 'shadows a global declaration'.  
#warning Unfortunately, it's the way this crud is coded and can't
#warning be fixed.  Just ignore them!
#warning
#include <gdome.h>
#warning
#warning ===========================================================
#warning
#else

#warning
#warning ===========================================================
#warning
#warning       Missing header files, disabling xmldump plugin
#warning
#warning           FOR MOST USERS THIS IS NOT A PROBLEM
#warning           ntop will build and run just fine... 
#warning
#warning Why?
#warning
#ifndef HAVE_GLIBCONFIG_H
#warning           glibconfig.h unavailable
#endif
#ifndef HAVE_GLIB_H
#warning           glib.h unavailable
#endif
#ifndef HAVE_GDOME_H
#warning           gdome.h unavailable
#endif
#ifndef CONST_XMLDUMP_PLUGIN_NAME
#warning           CONST_XMLDUMP_PLUGIN_NAME not defined
#endif
#warning
#warning ===========================================================
#warning
#endif

/*
 *  CONST_XML_VERSION
 *     Is the value used in the <ntop_dump_header ... xml_version=n ...> tag.
 *
 *     This MUST be incremented for each major (incompatible) change in the xml formats
 *
 *     It's here, vice globals-defines.h so you won't forget to update it when you
 *     update the code!
 */
#define CONST_XML_VERSION                   "1"  

    /* History:
       0 - ntop 3.0
       1 - ntop 3.1 (major reorg)
     */

#include  "xml_g_subversion.inc"

/*
 * Define the parm values for xmldump and the # of characters to test
 *  (e.g. with a TEST_LEN of 3, interference and interface both work)
 */
#define CONST_XMLDUMP_TEST_LEN              3
#define CONST_XMLDUMP_VERSION               "version"

/* Forward */
static int initXmldump(void);
static void termXmldump(u_char termNtop /* 0=term plugin, 1=term ntop */);
static void emptyHTTPhandler(char* url);
static void traceEvent_forked(int eventTraceLevel, char* file, int line, char * format, ...);
static void xmlDebug(char* file, int line, int level, char *format, ...);

#ifdef MAKE_WITH_XMLDUMP
GdomeDOMImplementation *domimpl;
GdomeDocument *doc;
GdomeElement *root,
             *elConfiguration,
             *elInternals,
             *elStatistics,
             *elHosts,
             *elInterfaces;
char *dtdURI;

struct sigaction xml_new_act, xml_old_act_SEGV;
volatile sig_atomic_t segv_count = 0;

static char hostName[MAXHOSTNAMELEN];
static int dumpHosts,
           dumpInterfaces,
           dumpConfiguration,
           dumpInternals,
           dumpStatistics;

#ifdef XMLDUMP_DEBUG
static int debugLevel=0;
#endif

static unsigned short inTraceEventForked=0;

jmp_buf siglongjmpEnv, siglongjmpBasicEnv;

/* ****************************** */

/* **** f o r w a r d **** */

static int dumpXML(char * url);
static void handleXmldumpHTTPrequest(char* url);

GdomeElement * _newxml(char * filename, int linenum,
                       GdomeElement * parent,
                       char * nodename,
                       ...);
GdomeElement * dumpXML_hosts(void);
GdomeElement * dumpXML_interfaces(void);
GdomeElement * dumpXML_configuration(void);
GdomeElement * dumpXML_internals(void);
GdomeElement * dumpXML_statistics(void);
int dumpXML_writeout(void);
RETSIGTYPE xml_sighandler(int signo, siginfo_t *siginfo, void *ptr);

#endif

static unsigned short initialized = 0;

/* ****************************** */
#define CONST_XML_DUMP_XML                  "dump.xml"

static ExtraPage xmlExtraPages[] = {
  { NULL, CONST_XML_DUMP_XML, "Dump" },
  { NULL, NULL, NULL }
};

static PluginInfo pluginInfo[] = {
  { VERSION, /* current ntop version */
    "XML data dump",
    "Dumps ntop internal table structures in an xml format.\n"
    "<br><br><em>Click <a href=\"" CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "/" CONST_XML_DUMP_XML "\">here</a> "
    "to open the actual dump in your browser</em>."
    "<br><i>This may take a LONG time - see the caution on the plugin configuration page.</i>",
    "3.1", /* plugin version */
    "<A HREF=\"http://www.ntopsupport.com\">B.Strauss</A>",
#ifdef CONST_XMLDUMP_PLUGIN_NAME
//This seems odd, but we need CONST_XMLDUMP_PLUGIN_NAME in http.c's URLsecurity
//so the constant should be in globals-defines.h - this is just in case...
    CONST_XMLDUMP_PLUGIN_NAME, /* http://<host>:<port>/plugins/shortPluginName */
#else
    "xmldump",                 /* http://<host>:<port>/plugins/shortPluginName */
#endif
    0, /* Active by default */
    ConfigureOnly,
    1, /* Inactive setup */
    initXmldump, /* InitFunc   */
    termXmldump, /* TermFunc   */
    NULL,    /* PluginFunc */
#ifdef MAKE_WITH_XMLDUMP
    handleXmldumpHTTPrequest,
#else
    emptyHTTPhandler, /* no handler */
#endif
    NULL, /* no host creation/deletion handle */
    NULL, /* no capture */
    NULL, /* no status */
    xmlExtraPages  /* extra page for the dump */
  }
};

/* Plugin entry fctn */
#ifdef STATIC_PLUGIN
PluginInfo* myPluginEntryFctn() {
#else
  PluginInfo* PluginEntryFctn() {
#endif

  /* Code here is run during ntop's startup, regardless of whether the plugin is active */

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "XMLDUMP: Welcome to %s. (C) 2003-2004 by Burton Strauss",
             pluginInfo->pluginName);

  return(pluginInfo);
}

/* This must be here so it can access the struct PluginInfo, above */
static void setPluginStatus(char * status)
   {
       if (pluginInfo->pluginStatusMessage != NULL)
           free(pluginInfo->pluginStatusMessage);
       if (status == NULL) {
           pluginInfo->pluginStatusMessage = NULL;
       } else {
           pluginInfo->pluginStatusMessage = strdup(status);
       }
   }

/* ****************************** */

static void emptyHTTPhandler(char* url) {
  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("XML Dump", NULL, 0);
  printFlagedWarning("This feature is not available as ntop<br>has not been compiled with XML support.");
  printHTMLtrailer();
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void xmlDebug(char* file, int line, 
              int level, char *format, ...) {
#ifdef XMLDUMP_DEBUG
  char cBuf[LEN_GENERAL_WORK_BUFFER],
       fBuf[LEN_GENERAL_WORK_BUFFER];
  va_list va_ap;
  int rc;

  if(level <= debugLevel) {
    memset(&cBuf, 0, sizeof(cBuf));
    memset(&fBuf, 0, sizeof(fBuf));

    rc = snprintf(fBuf, sizeof(fBuf), "<!-- %s %s(%d) -->\n", format, file, line);
    if(rc < 0)
      traceEvent_forked(CONST_TRACE_ERROR, "fBuf too short @ %s:%d", file, line);
    else if(rc >= sizeof(fBuf))
      traceEvent_forked(CONST_TRACE_ERROR, "fBuf too short @ %s:%d (increase to at least %d)", file, line, rc);

    va_start (va_ap, format);
    rc = vsnprintf(cBuf, sizeof(cBuf), fBuf, va_ap);
    if(rc < 0)
      traceEvent_forked(CONST_TRACE_ERROR, "cBuf too short @ %s:%d", file, line);
    else if(rc >= sizeof(cBuf))
      traceEvent_forked(CONST_TRACE_ERROR, "cBuf too short @ %s:%d (increase to at least %d)", file, line, rc);
    else {
      char*lessThan;
      lessThan = strchr(&cBuf[1], '<');
      if(lessThan != NULL)
        memcpy(lessThan, "... -->\n\0", sizeof("... -->\n\0"));
      sendString(cBuf);
    }
          
    va_end (va_ap);
  }
#endif /* XMLDUMP_DEBUG */
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*  N O T E S :

     We don't output the data from the structure in the exact same
     organization as it really is (myGlobals).  Instead we break it
     up into the logical organization that should make the data of use
     to outside manipulation...

        node name        - description

        ntop_dump_header - critical info about the xml file.
        version_c_header - (optional) information about how ntop was built/compiled
        invoke           - (optional) information about how ntop was invoked


   So, How do I add something to 1) an existing structure and 2) a new structure

     Remember to increase the xml version number after any addition.

  1) To add something to an existing structure, find the XML lines for the rest of
     the structure and just craft a new XML line in with the rest.  This will automatically
     cause code to be generated in the xml/[sg]_xxxxx.inc file and cause it to be picked
     up.

  2) To add something totally new, first figure out where it belongs in the dtd.  Say you
     have a new structure, struct XyX being added to myGlobals.

     Add the skeleton stuff to xmldump.c:

  GdomeElement * dumpXML_xyx(XyX * el) {
      int rc=0;
      GdomeException exc;
      GdomeElement *elWork;

  #ifdef XMLDUMP_DEBUG
      traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_xyx");
  #endif

      #include "xml_s_xyx.inc"

  #ifdef XMLDUMP_DEBUG
      traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_xyx");
  #endif

      return 0;
  }

    Then, after the struct ... {} ...; stuff, add the various XML doc lines to define
    the variables for the new structure:

  XMLSECTIONBEGIN xml_s_xyx.inc work el
    XML b      isLocked                       Work  ""
    XML n      maxLockedDuration              Work  ""
  XMLSECTIONEND name


   Note how the el in the XMLSECTIONBEGIN matches up with the variable in the
GdomeElement * newxml_xyx() line!

   In those places where there is a struct xyx, add the XML line:

    XML xyx      xyx_item                     Work  ""

   Finally, add a "struct xyx" line to processstruct.list so that xmldump.awk knows how to
reference the new structure.

   Next time the files are rebuilt, the xml_s_xyx.inc file should be created.

 */

/* ***************************** */

static int initXmldump(void) {

#ifndef MAKE_WITH_XMLDUMP

  traceEvent(CONST_TRACE_ERROR, "XMLDUMP: Missing header files at compile time, xmldump disabled");
  setPluginStatus("Missing header files at compile time, xmldump disabled");
  return(-1); /* init failed */

#else
  char value[1024];

  /* Code here is run during the plugin startup, so only if it's active */

  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "XMLDUMP: Welcome to ntop xmldump (init)");

//  memset(&buf, 0, sizeof(buf));
//  memset(&buf2, 0, sizeof(buf2));
//  memset(&buf3, 0, sizeof(buf3));
//  memset(&buf4, 0, sizeof(buf4));
//  memset(&buf5, 0, sizeof(buf5));
//  memset(&buf6, 0, sizeof(buf6));
//  memset(&buf7, 0, sizeof(buf7));

  if(gethostname(hostName, MAXHOSTNAMELEN) != 0)
    strncpy(hostName, "127.0.0.1", MAXHOSTNAMELEN);
  else {
    traceEvent(CONST_TRACE_NOISY, "XMLDUMP: On this system, gethostname() returned '%s'", hostName);

    if(strcmp(hostName, myGlobals.runningPref.domainName) == 0) {
      /* The returned hostName doesn't appear to have the domainName in it... */
      traceEvent(CONST_TRACE_NOISY, "XMLDUMP: Appending the domain name, '%s'", myGlobals.runningPref.domainName);
      safe_snprintf(__FILE__, __LINE__, hostName, sizeof(hostName), "%s.%s", hostName, myGlobals.runningPref.domainName);
    }
  }

  if(fetchPrefsValue("xmldump.hosts", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", TRUE);
    storePrefsValue("xmldump.hosts", value);
    dumpHosts = TRUE;
  } else {
    dumpHosts = atoi(value);
  }

  if(fetchPrefsValue("xmldump.interfaces", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", TRUE);
    storePrefsValue("xmldump.interfaces", value);
    dumpInterfaces = TRUE;
  } else {
    dumpInterfaces = atoi(value);
  }

  if(fetchPrefsValue("xmldump.internals", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", FALSE);
    storePrefsValue("xmldump.internals", value);
    dumpInternals = FALSE;
  } else {
    dumpInternals = atoi(value);
  }

  if(fetchPrefsValue("xmldump.configuration", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", FALSE);
    storePrefsValue("xmldump.configuration", value);
    dumpConfiguration = FALSE;
  } else {
    dumpConfiguration = atoi(value);
  }

  if(fetchPrefsValue("xmldump.statistics", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", FALSE);
    storePrefsValue("xmldump.statistics", value);
    dumpStatistics = FALSE;
  } else {
    dumpStatistics = atoi(value);
  }

  traceEvent(CONST_TRACE_NOISY, "XMLDUMP: Dump %s%s%s%s%s",
             dumpHosts == TRUE         ? " Hosts" : "",
             dumpInterfaces == TRUE    ? " Interfaces" : "",
             dumpInternals == TRUE     ? " Internals" : "",
             dumpConfiguration == TRUE ? " Configuration" : "",
             dumpStatistics == TRUE    ? " Statistics" : "");

#ifdef XMLDUMP_DEBUG
  if(fetchPrefsValue("xmldump.debug", value, sizeof(value)) == -1) {
    safe_snprintf(__FILE__, __LINE__, value, sizeof(value), "%d", 0);
    storePrefsValue("xmldump.debug", value);
    debugLevel = 0;
  } else {
    debugLevel = atoi(value);
  }
  traceEvent(CONST_TRACE_NOISY, "XMLDUMP: Debug Level %d", debugLevel);
#endif

  initialized = 1;
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "XMLDUMP: Plugin initialized");

  return(0);

#endif

}

/* ****************************** */

static void termXmldump(u_char termNtop /* 0=term plugin, 1=term ntop */) {

#ifdef MAKE_WITH_XMLDUMP

  traceEvent(CONST_TRACE_INFO, "XMLDUMP: Thanks for using ntop xmldump");
  traceEvent(CONST_TRACE_ALWAYSDISPLAY, "XMLDUMP: Done");

#endif

}

/* ****************************** */

  /* handle HTTP requests here */

static void handleXmldumpHTTPrequest(char* url) {

  char buf[LEN_GENERAL_WORK_BUFFER];

#ifdef XMLDUMP_DEBUG
  traceEvent(CONST_TRACE_NOISY, "XMLDUMP: Request is %s%s", url, initialized != 1 ? "- plugin is not initialized" : "");
#endif

  if(strstr(url, ".xml") != NULL) {

    if(initialized != 1) {
      /* Sorry, Charlie, the Plugin ain't active... */
      /* Send basic XML header so that comments are legal... */
      sendHTTPHeader(FLAG_HTTP_TYPE_XML, BITFLAG_HTTP_NO_CACHE_CONTROL, 1);
      sendString("<?xml version=\"1.0\" ?>\n"
                 "<!-- Invalid Request -->\n<request_invalid reason=\"plugin not active\"/>\n");
      return;
    }

    /* Process it */
    dumpXML(url);

#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
    if(myGlobals.childntoppid != 0)
      exit(0);  /* This is the child, just die */
#endif

    return;
  }

  memset(&buf, 0, sizeof(buf));

  sendHTTPHeader(FLAG_HTTP_TYPE_HTML, 0, 1);
  printHTMLheader("xmldump parameters", NULL, 0);

  sendString("<hr>\n<center>\n"
             "<p>This plugin is used to change ntop's xml dump parameter settings.</p>\n"
             "<p><b>Changes take affect immediately.</b></p></center>\n"
             "<br>\n");

#ifdef MAKE_WITH_XMLDUMP

  if(url != NULL) {
    char *urlPiece, *mainState, *key, *value;

    urlPiece = strtok_r(url, "&", &mainState);
    while(urlPiece != NULL) {

      key = strtok(url, "=");
      if(key != NULL) value = strtok(NULL, "="); else value = NULL;

      if(value && key) {
        if(strcmp(key, "hosts") == 0) {
          dumpHosts = atoi(value);
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpHosts);
          storePrefsValue("xmldump.hosts", buf);
        } else if(strcmp(key, "interfaces") == 0) {
          dumpInterfaces = atoi(value);
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpInterfaces);
          storePrefsValue("xmldump.interfaces", buf);
        } else if(strcmp(key, "configuration") == 0) {
          dumpConfiguration = atoi(value);
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpConfiguration);
          storePrefsValue("xmldump.configuration", buf);
        } else if(strcmp(key, "internals") == 0) {
          dumpInternals = atoi(value);
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpInternals);
          storePrefsValue("xmldump.internals", buf);
        } else if(strcmp(key, "statistics") == 0) {
          dumpStatistics = atoi(value);
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", dumpStatistics);
          storePrefsValue("xmldump.statistics", buf);
#ifdef XMLDUMP_DEBUG
        } else if(strcmp(key, "debug") == 0) {
          debugLevel = atoi(value);
          safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d", debugLevel);
          storePrefsValue("xmldump.debug", buf);
#endif
        }
      }
      urlPiece = strtok_r(NULL, "&", &mainState);
    }
  }

  /* *************************************** */


  sendString("<center>\n"
             "<table border=0 "TABLE_DEFAULTS">\n"
             "<tr "TR_ON">\n"
               "<th "TH_BG" align=\"left\" width=\"240\">Setting</th>\n"
               "<th "TH_BG" align=\"left\">Action</th>\n</tr>\n");

  /* ********** */

  sendString("<tr "TR_ON">\n"
             "<td "TD_BG">Dump per-host data</td>\n"
             "<td "TD_BG" align=\"left\"><form action=\"/"
             CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "\" method=get>\n");

  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"hosts\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              1,
              dumpHosts == TRUE ? " checked" : "",
              "Yes");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"hosts\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              0,
              dumpHosts == FALSE ? " checked" : "",
              "No");
  sendString(buf);
  sendString("<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  /* ********** */

  sendString("<tr "TR_ON">\n"
             "<td "TD_BG">Dump per-interface data</td>\n"
             "<td "TD_BG" align=\"left\"><form action=\"/"
             CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "\" method=get>\n");

  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"interfaces\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              1,
              dumpInterfaces == TRUE ? " checked" : "",
              "Yes");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"interfaces\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              0,
              dumpInterfaces == FALSE ? " checked" : "",
              "No");
  sendString(buf);
  sendString("<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  /* ********** */

  sendString("<tr "TR_ON">\n"
             "<td "TD_BG">Dump configuration settings</td>\n"
             "<td "TD_BG" align=\"left\"><form action=\"/"
             CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "\" method=get>\n");

  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"configuration\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              1,
              dumpConfiguration == TRUE ? " checked" : "",
              "Yes");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"configuration\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              0,
              dumpConfiguration == FALSE ? " checked" : "",
              "No");
  sendString(buf);
  sendString("<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  /* ********** */

  sendString("<tr "TR_ON">\n"
             "<td "TD_BG">Dump internal data</td>\n"
             "<td "TD_BG" align=\"left\"><form action=\"/"
             CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "\" method=get>\n");

  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"internals\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              1,
              dumpInternals == TRUE ? " checked" : "",
              "Yes");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"internals\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              0,
              dumpInternals == FALSE ? " checked" : "",
              "No");
  sendString(buf);
  sendString("<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  /* ********** */

  sendString("<tr "TR_ON">\n"
             "<td "TD_BG">Dump statistical data</td>\n"
             "<td "TD_BG" align=\"left\"><form action=\"/"
             CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "\" method=get>\n");

  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"statistics\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              1,
              dumpStatistics == TRUE ? " checked" : "",
              "Yes");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"statistics\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              0,
              dumpStatistics == FALSE ? " checked" : "",
              "No");
  sendString(buf);
  sendString("<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

  /* ********** */

#ifdef XMLDUMP_DEBUG

  sendString("<tr "TR_ON">\n"
             "<td "TD_BG">Debug Level</td>\n"
             "<td "TD_BG" align=\"left\"><form action=\"/"
             CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "\" method=get>\n");

  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"debug\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              0,
              debugLevel == 0 ? " checked" : "",
              "Off");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"debug\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              1,
              debugLevel == 1 ? " checked" : "",
              "Mild");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"debug\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              2,
              debugLevel == 2 ? " checked" : "",
              "Moderate");
  sendString(buf);
  safe_snprintf(__FILE__, __LINE__, buf,
              sizeof(buf),
              "<input TYPE=\"radio\" NAME=\"debug\" VALUE=%d%s>%s&nbsp;&nbsp;&nbsp;\n",
              3,
              debugLevel == 3 ? " checked" : "",
              "Heavy");
  sendString(buf);
  sendString("<INPUT TYPE=submit VALUE=Set></form></td></tr>\n");

#endif

  /* ********** */

  sendString("</table>\n</center>\n");


  if(pluginInfo->pluginStatusMessage == NULL) {
    sendString("<p>Click <a href=\"/" CONST_PLUGINS_HEADER CONST_XMLDUMP_PLUGIN_NAME "/" CONST_XML_DUMP_XML "\">here</a> "
               "to open the actual dump in your browser.</p>\n"
               "<p><em>WARNING:</em>&nbsp;Generating this page may take a LONG time.\n");
#ifdef MAKE_WITH_FORK_COPYONWRITE
    sendString("This copy of <b>ntop</b> is built so that the dump will be of a frozen copy of the <b>ntop</b> data, "
               "which will be generated while <b>ntop</b> continues to process packets and accumulate new data.\n");
#else   
    sendString("This operating system does not allow for creation of a frozen copy of the <b>ntop</b> data, "
               "so generation of this page will be based upon the live data.  Because this page takes a long time "
               "to build, counts will be altered during page creation.  Thus, requesting this page may impact or "
               "be impacted by <b>ntop</b>'s actions as it continues to process packets.\n"
               "<i>If it locks up, well, you have been warned!</i>\n");
#endif 
    sendString("</p>\n");
  }

  /* *************************************** */

#else

  if(pluginInfo->pluginStatusMessage != NULL) {
    sendString("<p><b>Plugin disabled</b>: ");
    sendString(pluginInfo->pluginStatusMessage);
    sendString("</p>\n");
  }
#endif

  sendString("</CENTER>\n");

  printPluginTrailer(NULL, NULL);

  printHTMLtrailer();
}

//---------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------

#ifdef MAKE_WITH_XMLDUMP

/* internal functions */
GdomeElement * _newxml(char * filename, int linenum,
                       GdomeElement * parent,
                       char * nodename,
                       ...) {
    int rc=0, i, adjCntTotal = 0, adjCnt = 0;
    GdomeElement *temp_el;
    GdomeDOMString *temp_nodename, *temp_attrname, *temp_attrvalue;
    GdomeException exc;
    char *attrname, *attrvalue;
    unsigned char buf[LEN_GENERAL_WORK_BUFFER];
    int siglongjmpReturnValue;

    va_list ap;

    xmlDebug(__FILE__, __LINE__, 2, "START newxml()", "");

    memset(&buf, 0, sizeof(buf));

    /* Now set up our special protective environment for newxml something bad?  skip it and continue ... */
    if ((siglongjmpReturnValue = setjmp(siglongjmpEnv)) != 0) {
      /* We return here on an error ... since we couldn't create the node, we're done... */
      return(0);
    }

    /* setjmp() = 0, i.e. normal flow */
    if (nodename == NULL) {
        xmlDebug(__FILE__, __LINE__, 3, "...nodename NULL", "");
        temp_nodename = gdome_str_mkref("null");
    } else {
        adjCnt = 0;

        if (nodename == NULL) {
            temp_nodename = gdome_str_mkref ("(null)");
        } else {

            strncpy(buf, nodename, sizeof(buf)-1);
            for(i=0; i<strlen(buf); i++) {
              if(buf[i] > '\x7f' /* Invalid for UTF-8 string */) {
                buf[i]='.';
                adjCntTotal++;
                adjCnt++;
              }
            }
            temp_nodename = gdome_str_mkref (buf);
        }
    }

    if(adjCnt > 0)
      xmlDebug(__FILE__, __LINE__, 2, "...gdome_doc_createElement(, [0x%08x:%s],) w/ adj UTF8 chars", temp_nodename, temp_nodename->str);
    else
      xmlDebug(__FILE__, __LINE__, 3, "...gdome_doc_createElement(, [0x%08x:%s],)", temp_nodename, temp_nodename->str);

    temp_el = gdome_doc_createElement (doc, temp_nodename, &exc);
    if (exc) {
        traceEvent_forked(CONST_TRACE_ERROR,
                   "XMLDUMP:      newxml() at %d(%s), createElement failed, Exception #%d",
                   linenum,
                   filename,
                   exc);
        rc=(int)exc;
    }
    if (temp_nodename != NULL)
      gdome_str_unref(temp_nodename);

    /* set attributes */
    if (rc == 0) {

        xmlDebug(__FILE__, __LINE__, 2, "...Processing attributes", "");
        va_start(ap, nodename);
        attrname=va_arg(ap, char *);
        xmlDebug(__FILE__, __LINE__, 3, "......va_start()/va_arg gives %s(0x%08x)", attrname, attrname);

        while ( (attrname != NULL) && (strcmp(attrname, "__sentinel__") != 0) ) {

            /* Now set up our special protective environment for newxml something bad? */
            if ((siglongjmpReturnValue = setjmp(siglongjmpEnv)) != 0) {
              /* We return here on an error ... just do the next node... */
              traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: Attribute %s (signal %d) from %s(%d)",
                                attrname,
                                siglongjmpReturnValue,
                                filename,
                                linenum);
              attrname=va_arg(ap, char *);
              continue;
            }

            /* setjmp() = 0, i.e. normal flow */

            adjCnt = 0;

            attrvalue=va_arg(ap, char *);
            if ( (attrvalue != NULL) &&
                 (strcmp(attrvalue, "__sentinel__") == 0) ) {

                xmlDebug(__FILE__, __LINE__, 3, "......found __sentinel__", "");

                break;
            }
            if ( (attrvalue != NULL) &&
                 (strcmp(attrname, "description") == 0) &&
                 (strcmp(attrvalue, "") == 0) ) {

                xmlDebug(__FILE__, __LINE__, 3, "......skip null description", "");

                break;
            }

            temp_attrname = gdome_str_mkref (attrname);

            if (attrvalue == NULL) {
                temp_attrvalue = gdome_str_mkref ("(null)");
            } else {

                strncpy(buf, attrvalue, sizeof(buf)-1);
                for(i=0; i<strlen(buf); i++) {
                  if(buf[i] > '\x7f' /* Invalid for UTF-8 string */) {
                    buf[i]='.';
                    adjCntTotal++;
                    adjCnt++;
                  }
                }
                temp_attrvalue = gdome_str_mkref (buf);
            }

            if(adjCnt > 0)
              xmlDebug(__FILE__, __LINE__, 2, "...gdome_el_setAttribute(, [0x%08x:%s], [0x%08x:%s],) w/ adj UTF8 chars",
                       temp_attrname, temp_attrname->str,
                       temp_attrvalue, temp_attrvalue->str);
            else
              xmlDebug(__FILE__, __LINE__, 3, "...gdome_el_setAttribute(, [0x%08x:%s], [0x%08x:%s],)",
                       temp_attrname, temp_attrname->str,
                       temp_attrvalue, temp_attrvalue->str);

            gdome_el_setAttribute (temp_el, temp_attrname, temp_attrvalue, &exc);

            if (exc) {
                traceEvent_forked(CONST_TRACE_ERROR,
                           "XMLDUMP:      newxml() at %d(%s), el_setAttribute failed, Exception #%d",
                           linenum,
                           filename,
                           exc);
                rc=(int)exc;
            }
            gdome_str_unref(temp_attrname);
            gdome_str_unref(temp_attrvalue);

            attrname=va_arg(ap, char *);
            xmlDebug(__FILE__, __LINE__, 3, "......va_arg found %s", attrname);
        }

        va_end(ap);

        if(adjCntTotal > 0) {  
          temp_attrname = gdome_str_mkref ("warning");
          temp_attrvalue = gdome_str_mkref ("Invalid UTF8 characters replaced by '.'s");
          gdome_el_setAttribute (temp_el, temp_attrname, temp_attrvalue, &exc);
          if (exc) {
              traceEvent_forked(CONST_TRACE_ERROR,
                         "XMLDUMP:      newxml() at %d(%s), el_setAttribute failed, Exception #%d",
                         linenum,
                         filename,
                         exc);
          }
          gdome_str_unref(temp_attrname);
          gdome_str_unref(temp_attrvalue);
        }

    }

    /* append to parent */
    if ( (rc == 0) && (parent != NULL) ) {
        xmlDebug(__FILE__, __LINE__, 3, "...gdome_el_appendChild()", "");
        gdome_el_appendChild (parent, (GdomeNode *)temp_el, &exc);
        if (exc) {
            traceEvent_forked(CONST_TRACE_ERROR,
                       "XMLDUMP:      newxml() at %d(%s), el_appendChild failed, Exception #%d",
                       linenum,
                       filename,
                       exc);
        }
    }

    xmlDebug(__FILE__, __LINE__, 2, "END newxml() rc=%d", rc);

    if (rc != 0) {
        return NULL;
    } else {
        return temp_el;
    }
}

/* macros */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                                   Generic                                     */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define newxmlna(parent, name) \
      _newxml(__FILE__, __LINE__, parent, name, "__sentinel__")

#define newxml(parent, name, ... ) \
      _newxml(__FILE__, __LINE__, parent, name, __VA_ARGS__, "__sentinel__")

#define newxml_empty(parent, name, description) \
  newxml(parent, name, \
         "description", description)

#define newxml_simplenoyes(parent, name, booleanvar, description) \
  newxml(parent, name, \
         "value", booleanvar == 0 ? "No" : "Yes", \
         "description", description)

#define newxml_smartstring(parent, name, stringvar, description) \
  _newxml_smartstring(__FILE__, __LINE__, parent, name, stringvar, sizeof(stringvar), description)

#define newxml_namedstring(parent, name, stringvar, description, stringname) \
  newxml(parent, name, \
         stringname, stringvar, \
         "description", description)

/* WARNING: The following DO NOT return a value! */

#define newxml_simplehex(parent, name, hexvar, description) {\
   safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "0x%x", hexvar); \
  newxml(parent, name, \
         "value", buf, \
         "description", description); \
}

#define newxml_fd_set(parent, name, hexvar, description) \
   newxml_simplehex(parent, name, hexvar, description)

#define newxml_simplenumeric(parent, name, numericvar, description, format) {\
   safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), format, numericvar); \
  newxml(parent, name, \
         "value", buf, \
         "description", description); \
}

#define newxml_namednumeric(parent, name, numericvar, description, format, fieldname) { \
   safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), format, numericvar); \
  newxml(parent, name, \
         fieldname, buf, \
         "description", description); \
}

#define newxml_simplefloat(parent, name, numericvar, description, format) {\
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), format, numericvar); \
  newxml(parent, name, \
         "value", buf, \
         "description", description); \
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                forward declarations for intelligent ones                      */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

GdomeElement * _newxml_smartstring(char * filename,
                     int linenum,
                     GdomeElement * parent,
                      char * nodename,
                     char * stringvar,
                     int sizeofstringvar,
                      char * description);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                forward declarations for structs                               */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Hand-coded: Please keep them in alphabetic order for ease of finding them...  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
//??GdomeElement * newxml_hostaddr(GdomeElement * parent,
//??                       char * nodename,
//??                       HostAddr * input,
//??                       char * description);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Auto-generated from XMLSTRUCT:                                                */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "xml_s_simple_forward.inc"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                              Special types                                    */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Please keep them in alphabetic order for ease of finding them...              */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// #define newxml_hostserial_index(parent, name, hostserial_var, index_var, description) \
//     safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", hostserial_var); \
//     safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%d", index_var); \
//     newxml(parent, name, \
//                                "index", buf2, \
//                                "value", buf, \
//                                "description", description); \
// }

#define newxml_ethaddress(parent, name, ethaddress_var, description) { \
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", \
               ethaddress_var[0], \
               ethaddress_var[1], \
               ethaddress_var[2], \
               ethaddress_var[3], \
               ethaddress_var[4], \
               ethaddress_var[5]); \
  newxml(parent, name, "value", buf, "description", description); \
}

#define newxml_in_addr(parent, name, in_addr_var, description) { \
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d.%d.%d.%d", \
               (int) ((in_addr_var.s_addr >> 24) & 0xff), \
               (int) ((in_addr_var.s_addr >> 16) & 0xff), \
               (int) ((in_addr_var.s_addr >>  8) & 0xff), \
               (int) ((in_addr_var.s_addr >>  0) & 0xff)); \
  safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%u", in_addr_var.s_addr); \
  newxml(parent, name, "value", buf2, "interpreted", buf, "description", description); \
}

#ifdef INET6
#define newxml_in6_addr(parent, name, in6_addr_var, description) { \
  inet_ntop(AF_INET6, &in6_addr_var, buf, sizeof(buf)); \
  newxml(parent, name, "value", buf, "description", description); \
}
#else
#define newxml_in6_addr(parent, name, in6_addr_var, description) { \
  error("in6_addr referenced w/o INET6 defined"); \
}
#endif

#define newxml_time_t(parent, name, time_t_var, description) { \
  if(time_t_var > 0) { \
    char bufT1[sizeof("Wed Jun 30 21:49:08 1993\n")+1], \
         bufT2[sizeof("0000000000")+1]; \
    memset(&bufT1, 0, sizeof(bufT1)); \
    memset(&bufT2, 0, sizeof(bufT2)); \
    memcpy(&bufT1, ctime(&time_t_var), sizeof("Wed Jun 30 21:49:08 1993\n")-1); \
    bufT1[sizeof("Wed Jun 30 21:49:08 1993\n")-2] = '\0'; \
    safe_snprintf(__FILE__, __LINE__, bufT2, sizeof(bufT2), "%d", time_t_var); \
    newxml(parent, name, "value", bufT2, "interpreted", bufT1, "description", description); \
  } else { \
    newxml(parent, name, "value", "0", "description", description); \
  } \
}

#define newxml_timeval(parent, name, timeval_var, description) { \
  if((timeval_var.tv_sec > 0) || (timeval_var.tv_usec > 0) ) { \
    char bufT1[sizeof("Wed Jun 30 21:49:08 1993\n")+1], \
         bufT2[sizeof("Wed Jun 30 21:49:08 1993 0.000000")+1], \
         bufT3[sizeof("0000000000.000000")+1]; \
    memset(&bufT1, 0, sizeof(bufT1)); \
    memset(&bufT2, 0, sizeof(bufT2)); \
    memset(&bufT3, 0, sizeof(bufT3)); \
    memcpy(&bufT1, ctime(&timeval_var.tv_sec), sizeof("Wed Jun 30 21:49:08 1993\n")-1); \
    bufT1[sizeof("Wed Jun 30 21:49:08 1993\n")-2] = '\0'; \
    safe_snprintf(__FILE__, __LINE__, bufT2, sizeof(bufT2), "%s 0.%06d", bufT1, timeval_var.tv_usec); \
    safe_snprintf(__FILE__, __LINE__, bufT3, sizeof(bufT3), "%d.%06d", timeval_var.tv_sec, timeval_var.tv_usec); \
    newxml(parent, name, "value", bufT3, "interpreted", bufT2, "description", description); \
  } else { \
    newxml(parent, name, "value", "0", "description", description); \
  } \
}

#ifdef WIN32
  #define newxml_counter(parent, name, counter_var, description) { \
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%f", counter_var); \
      newxml(parent, name, "value", buf, "description", description); \
  }
  #define newxml_trafficcounter(parent, name, trafficcounter_var, description) { \
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%f", trafficcounter_var.value); \
      newxml(parent, name, "value", buf, \
             "modified", trafficcounter_var.modified ? "true" : "false", \
             "description", description); \
  }
#else
  #define newxml_counter(parent, name, counter_var, description) { \
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%llu", counter_var); \
      newxml(parent, name, "value", buf, "description", description); \
  }
  #define newxml_trafficcounter(parent, name, trafficcounter_var, description) { \
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%llu", trafficcounter_var.value); \
      newxml(parent, name, "value", buf, \
             "modified", trafficcounter_var.modified ? "true" : "false", \
             "description", description); \
  }
#endif


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                              Intelligents                                     */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

GdomeElement * _newxml_smartstring(char * filename,
                     int linenum,
                     GdomeElement * parent,
                      char * nodename,
                     char * stringvar,
                     int sizeofstringvar,
                      char * description) {
int i;
unsigned char buf[LEN_GENERAL_WORK_BUFFER];

/* 'Strings' can be arrays of chars or pointers to chars (null terminated)
 figure which it is and handle it smartly! */


#if (XMLDUMP_DEBUG >= 3)
traceEvent_forked(CONST_TRACE_INFO,
                  "XMLDUMP_DEBUG: newxml_smartstring(... 0x%08x(%d), '%s') from %s(%d)",
                  stringvar, sizeofstringvar, description, filename, linenum);
#endif

memset(&buf, 0, sizeof(buf));

if(sizeofstringvar == sizeof(char *)) {
  if(stringvar == NULL) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "(NULL)");
  } else {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s", stringvar);
  }
} else {
  if(stringvar[0] == '\0') {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "(empty)");
  } else {
    strncpy(buf, stringvar, sizeofstringvar);
  }
}

/* Use _newxml not the define so we pass file/line from OUR caller */
_newxml(filename, linenum,
        parent, nodename,
                            "value", buf,
                            "description", description,
                            "__sentinel__");

#if (XMLDUMP_DEBUG >= 3)
traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: newxml_smartstring() OK");
#endif

}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                              structs                                          */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Hand-coded: Please keep them in alphabetic order for ease of finding them...  */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
//??GdomeElement * newxml_hostaddr(GdomeElement * parent,
//??                       char * nodename,
//??                       HostAddr * input,
//??                       char * description) {
//??
//??  GdomeException exc;
//??
//??#ifdef INET6
//??  if(input->hostFamily == AF_INET6) {
//??//      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d.%d.%d.%d",
//??//                   (int) ((input._hostIp4Address.s_addr >> 24) & 0xff),
//??//                   (int) ((input._hostIp4Address.s_addr >> 16) & 0xff),
//??//                   (int) ((input._hostIp4Address.s_addr >>  8) & 0xff),
//??//                   (int) ((input._hostIp4Address.s_addr >>  0) & 0xff));
//??//      safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%u", input._hostIp4Address.s_addr);
//??
//??//      newxml(parent, nodename,
//??//                                                 "family", "AF_INET6",
//??//                                                 "value", buf2,
//??//                                                 "interpreted", buf,
//??//                                                 "description", description);
//??  } else {
//??#endif
//??
//??    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d.%d.%d.%d",
//??                 (int) ((input->addr._hostIp4Address.s_addr >> 24) & 0xff),
//??                 (int) ((input->addr._hostIp4Address.s_addr >> 16) & 0xff),
//??                 (int) ((input->addr._hostIp4Address.s_addr >>  8) & 0xff),
//??                 (int) ((input->addr._hostIp4Address.s_addr >>  0) & 0xff));
//??    safe_snprintf(__FILE__, __LINE__, buf2, sizeof(buf2), "%u", input->addr._hostIp4Address.s_addr);
//??
//??    newxml(parent, nodename,
//??                                                 "family", "AF_INET",
//??                                                 "value", buf2,
//??                                                 "interpreted", buf,
//??                                                 "description", description);
//??
//??#ifdef INET6
//??  }
//??#endif
//??}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Auto-generated from XMLSTRUCT:                                                */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "xml_s_simple.inc"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Worker-bee functions:                                                         */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static GdomeElement * dumpXML_versioncHeader(GdomeElement * elParent) {

  GdomeElement *elWork;

  xmlDebug(__FILE__, __LINE__, 2, "START dumpXML_versioncHeader()", "");

  elWork = newxmlna(elParent, "version_c_header");
  /* Parameters from version.c */
  newxml_smartstring(elWork, "ntop_version",       version,               "");
  newxml_smartstring(elWork, "buildDate",          buildDate,             "");
  newxml_smartstring(elWork, "author",             author,                "");
  newxml_smartstring(elWork, "osName",             osName,                "");
  newxml_smartstring(elWork, "dotconfigure",       configure_parameters,  "");
  newxml_smartstring(elWork, "dotconfigureDate",   configureDate,         "");
  newxml_smartstring(elWork, "host_system_type",   host_system_type,      "");
  newxml_smartstring(elWork, "target_system_type", target_system_type,    "");
  newxml_smartstring(elWork, "compiler_cflags",    compiler_cflags,       "");
  newxml_smartstring(elWork, "include_path",       include_path,          "");
  newxml_smartstring(elWork, "system_libs",        system_libs,           "");
  newxml_smartstring(elWork, "install_path",       install_path,          "");
#ifdef MAKE_WITH_I18N
  newxml_smartstring(elWork, "locale_dir",         locale_dir,            "");
#endif
  newxml_smartstring(elWork, "os_or_distro",       distro,                "");
  newxml_smartstring(elWork, "release_or_kernel",  release,               "");
  newxml_smartstring(elWork, "forced_runtime_parameters", force_runtime,  "");

  xmlDebug(__FILE__, __LINE__, 2, "END   dumpXML_versioncHeader()", "");

  return elParent;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static GdomeElement * dumpXML_createHeader(void) {

   GdomeElement *elHeader;
   time_t now;
   int stableDump;
  char buf[LEN_GENERAL_WORK_BUFFER],
       bufT[LEN_TIMEFORMAT_BUFFER];

  memset(&buf, 0, sizeof(buf));

  xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_createHeader()", "");

#ifdef MAKE_WITH_FORK_COPYONWRITE
  if(myGlobals.childntoppid != 0)
    stableDump  = TRUE /* COPYONWRITE and a childpid means we're dumping from an fork()ed copy */;
  else
    stableDump  = FALSE;
#else
   stableDump    = FALSE;
#endif

  xmlDebug(__FILE__, __LINE__, 2, "...dump is%s stable", stableDump == TRUE ? "" : " not");

   now  = time(NULL);
  memset(&bufT, 0, sizeof(bufT));
  formatTime(&now, bufT, sizeof(bufT)),
  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", now);

  elHeader = newxml(root, "ntop_dump_header",
                          "epochdate",     buf,
                          "date",          bufT,
                          "hostName",      hostName,
                          "xml_version",   CONST_XML_VERSION "." CONST_XML_SUBVERSION,
                          "stable",        stableDump == TRUE ? "Yes" : "No");


  xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_createHeader()", "");

   return elHeader;
}


GdomeElement * dumpXML_hosts(void){
  int rc=0, i;
  GdomeElement *elWork, *elWork2, *elWork3;

  xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_hosts()", "");

  #include "xml_g_hosts.inc"

  xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_hosts()", "");

  return elHosts;
}

GdomeElement * dumpXML_interfaces(void){
   int rc=0, i;
  GdomeElement *elWork, *elWork2, *elWork3;

  xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_interfaces()", "");

  #include "xml_g_intf.inc"

  xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_interfaces()", "");

  return elInterfaces;
}

GdomeElement * dumpXML_configuration(void){
  int rc=0, i;
  GdomeElement *elWork, *elWork2, *elWork3;

  xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_configuration()", "");

  #include "xml_g_cfg.inc"

  dumpXML_versioncHeader(elConfiguration);

  xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_configuration()", "");

  return elConfiguration;
}

GdomeElement * dumpXML_statistics(void){
  int rc=0, i;
  GdomeElement *elWork, *elWork2, *elWork3;

  xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_statistics()", "");

  #include "xml_g_stat.inc"

  xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_statistics()", "");

  return elStatistics;
}

GdomeElement * dumpXML_internals(void){
  int rc=0, i;
  GdomeElement *elWork, *elWork2, *elWork3;

  xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_internals()", "");

  #include "xml_g_int.inc"

  xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_internals()", "");

  return elInternals;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

int dumpXML_writeout(void) {

    GdomeDocumentType* dt;
    GdomeException exc;
    GdomeDOMString *name, *systemId;

    FILE *fdTemp;
    int len, rc;
    char tmpFileName[NAME_MAX],
         tmpStr[LEN_FGETS_BUFFER], /* Use sizeof()-1 so we have an Extra \0 for strlen() */
         buf[LEN_GENERAL_WORK_BUFFER];
    char * doctypeHeader;
    int totalLen=0;

    memset(&tmpFileName, 0, sizeof(tmpFileName));
    memset(&tmpStr, 0, sizeof(tmpStr));
    memset(&buf, 0, sizeof(buf));

    xmlDebug(__FILE__, __LINE__, 1, "START dumpXML_writeout()", "");

    /* Output the DOM tree
     *
     *    What's special here is:
     *
     *     - the handling of the 1st block - we may have to force the doctype line!
     *
     */

    /* Create a unique temp name and have gdome dump the generated xml to it.
     *
     * We can't use util.c's getNewRandomFile() as we need the NAME not the FD,
     * but we generate this the same way...
     */

#ifndef WIN32
    safe_snprintf(__FILE__, __LINE__, tmpFileName, sizeof(tmpFileName), "%s-%lu", CONST_XML_TMP_NAME,
            myGlobals.numHandledRequests[0]+myGlobals.numHandledRequests[1]);
#else
    tmpnam(tmpFileName);
#endif

    xmlDebug(__FILE__, __LINE__, 2, "...Dumping dom to temp file '%s'", tmpFileName);

    rc = gdome_di_saveDocToFile(domimpl, doc, tmpFileName, GDOME_SAVE_LIBXML_INDENT, &exc);
    xmlDebug(__FILE__, __LINE__, 3, "...Exception %d rc %d", exc, rc);
    if (exc) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: saveDocToFile(): failed, Exception #%d", exc);
        return 1;
    } else if (rc != TRUE) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: saveDocToFile(): failed, rc FALSE");
        return 1;
    }

    /* Open the temp file we created and start echoing it */
    fdTemp = fopen(tmpFileName, "rb");
    if (fdTemp == NULL) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: fopen(, \"rb\"), errno=%d", errno);
        return 1;
    }

    totalLen = len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fdTemp);

    /*
     * Copy the generated file out to the user
     *
     *    Special case if the 1st block has the <?XML header
     *
     *      First: Skip over the <? xml ?> header and it's \n
     *          (we've already written this at the start of dumpXML())
     *
     *      Second: Check if the next part is NOT <!DOCTYPE> 
     *          and force one in if we need it.
     *
     *    Then: Output the rest of the block
     *        (this would include the DOCTYPE if we did find it in the file, above)
     *
     *    And finally just read each block and write it out until eof or an error...
     *        (do remember to dump the last, partial block...)
     */

    if( (len > 0) &&
         ( (doctypeHeader = strstr(tmpStr, "?>")) != NULL) ) {
        doctypeHeader += 3;

        if (strncmp(doctypeHeader, "<!DOCTYPE", sizeof("<!DOCTYPE")) != 0) {
            safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "<!DOCTYPE %s SYSTEM \"%s\">\n",
                                           CONST_XML_DOCTYPE_NAME,
                                           dtdURI);
            sendString(buf);
        }

        sendStringLen(doctypeHeader, len-(doctypeHeader-tmpStr));
        len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fdTemp);
        totalLen += len;
    }

    while ((!feof(fdTemp)) && (!ferror(fdTemp))) {
        sendStringLen(tmpStr, len);
        len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fdTemp);
        totalLen += len;
    }

    if(len > 0) {
        /* Send last, partial, buffer */
        sendStringLen(tmpStr, len);
        totalLen += len;
    }

    if(ferror(fdTemp)) {
      traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP_DEBUG: fread() error");
    }

    fclose(fdTemp);

#ifdef XMLDUMP_DEBUG
    /* Debug? Save the file if we're > 0 */
    if(debugLevel == 0)
#endif
      unlink(tmpFileName);

    xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML_writeout()", "");

    return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

RETSIGTYPE xml_sighandler(int signo, siginfo_t *siginfo, void *ptr) {
  static int msgSent = 0;
  int i;
  void *array[20];
  size_t size;
  char **strings;

  signal(SIGSEGV, SIG_DFL);

#ifdef HAVE_BACKTRACE
  /* Grab the backtrace before we do much else... */
  size = backtrace(array, 20);
#endif

  if(signo == SIGSEGV)
    segv_count++;

  if(++msgSent<10) {

    if(inTraceEventForked==1) {
      /* died in traceEvent_forked()?  Don't recurse */
      traceEvent(CONST_TRACE_FATALERROR, "XMLDUMP: caught signal %d %s errno(%d) code(%d)",
                 signo,
                 signo == SIGHUP ? "SIGHUP" :
                 signo == SIGINT ? "SIGINT" :
                 signo == SIGQUIT ? "SIGQUIT" :
                 signo == SIGILL ? "SIGILL" :
                 signo == SIGABRT ? "SIGABRT" :
                 signo == SIGFPE ? "SIGFPE" :
                 signo == SIGKILL ? "SIGKILL" :
                 signo == SIGSEGV ? "SIGSEGV" :
                 signo == SIGPIPE ? "SIGPIPE" :
                 signo == SIGALRM ? "SIGALRM" :
                 signo == SIGTERM ? "SIGTERM" :
                 signo == SIGUSR1 ? "SIGUSR1" :
                 signo == SIGUSR2 ? "SIGUSR2" :
                 signo == SIGCHLD ? "SIGCHLD" :
#ifdef SIGCONT
                 signo == SIGCONT ? "SIGCONT" :
#endif
#ifdef SIGSTOP
                 signo == SIGSTOP ? "SIGSTOP" :
#endif
#ifdef SIGBUS
                 signo == SIGBUS ? "SIGBUS" :
#endif
#ifdef SIGSYS
                 signo == SIGSYS ? "SIGSYS"
#endif
                 : "other",
                 siginfo->si_errno,
                 siginfo->si_code);
    } else {

      traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: caught signal %d %s errno(%d) code(%d)",
                        signo,
                        signo == SIGHUP ? "SIGHUP" :
                        signo == SIGINT ? "SIGINT" :
                        signo == SIGQUIT ? "SIGQUIT" :
                        signo == SIGILL ? "SIGILL" :
                        signo == SIGABRT ? "SIGABRT" :
                        signo == SIGFPE ? "SIGFPE" :
                        signo == SIGKILL ? "SIGKILL" :
                        signo == SIGSEGV ? "SIGSEGV" :
                        signo == SIGPIPE ? "SIGPIPE" :
                        signo == SIGALRM ? "SIGALRM" :
                        signo == SIGTERM ? "SIGTERM" :
                        signo == SIGUSR1 ? "SIGUSR1" :
                        signo == SIGUSR2 ? "SIGUSR2" :
                        signo == SIGCHLD ? "SIGCHLD" :
#ifdef SIGCONT
                        signo == SIGCONT ? "SIGCONT" :
#endif
#ifdef SIGSTOP
                        signo == SIGSTOP ? "SIGSTOP" :
#endif
#ifdef SIGBUS
                        signo == SIGBUS ? "SIGBUS" :
#endif
#ifdef SIGSYS
                        signo == SIGSYS ? "SIGSYS"
#endif
                        : "other",
                        siginfo->si_errno,
                        siginfo->si_code);

      switch (signo) {
        case SIGCHLD:
          traceEvent_forked(CONST_TRACE_NOISY, "XMLDUMP: SIGCHLD status(%d)",
                            siginfo->si_status);
          break;
        case SIGSEGV:
          traceEvent_forked(CONST_TRACE_NOISY, "XMLDUMP: SIGSEGV addr(0x%08x)",
                            siginfo->si_addr);
          break;
      }

      traceEvent_forked(CONST_TRACE_NOISY, "XMLDUMP: int(%d) ptr(0x%08x)",
                        siginfo->si_int,
                        siginfo->si_ptr);

#ifdef HAVE_BACKTRACE
      if(size < 2) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: BACKTRACE:         **unavailable!");
      } else {

        /* Dump the backtrace */
        strings = (char**)backtrace_symbols(array, size);
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: BACKTRACE:     backtrace is:");
        /* Ignore the 0th entry, that's our cleanup() */
        for (i=1; i<size; i++) 
          traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: BACKTRACE:          %2d. %s", i, strings[i]);
      } /* size < 2 */
#endif /* HAVE_BACKTRACE */

    } /* inTraceEventForked!=1*/

  } /* msgSent < 10 */

  siglongjmp(siglongjmpEnv, signo);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef MAKE_WITH_XMLDUMP
static int dumpXML(char * url) {
    return(0);
}
#else
static int dumpXML(char * url) {
    GdomeDocumentType* dt;
    GdomeElement *el;
    GdomeException exc;
    GdomeNode *result;
    GdomeDOMString *name, *value;
    GdomeDOMString *qualifiedName;
    GdomeDOMString *namespaceURI;
    GdomeDOMString *publicId;
    GdomeDOMString *systemId;
    int rc=0;
    char *urlOptions;
#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
    int childpid;
#endif
    int siglongjmpReturnValue;
    char buf[LEN_GENERAL_WORK_BUFFER];

    struct timeval beforeFork, afterEvent;
    float elapsed;

    memset(&buf, 0, sizeof(buf));

#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
    if(myGlobals.runningPref.debugMode != 1) {

      xmlDebug(__FILE__, __LINE__, 1, "...fork()ing", "");

      gettimeofday(&beforeFork, NULL);

      /* To capture a stable point-in-time, grab the mutex and then fork() */
      accessMutex(&myGlobals.hostsHashMutex, "xmldump fork()");
      errno = 0;
      childpid = fork();
      if(childpid < 0) {
        releaseMutex(&myGlobals.hostsHashMutex);
        traceEvent(CONST_TRACE_ERROR, "An error occurred while forking ntop [errno=%d]..", errno);
        return(0);
      }

      if(childpid) {
        /* father process */
        releaseMutex(&myGlobals.hostsHashMutex);
        myGlobals.numChildren++;
        return(0);
      }

      gettimeofday(&afterEvent, NULL);

      if (afterEvent.tv_usec < beforeFork.tv_usec) {
        int nsec = (beforeFork.tv_usec - afterEvent.tv_usec) / 1000000 + 1;
        beforeFork.tv_usec -= 1000000 * nsec;
        beforeFork.tv_sec += nsec;
      }
      if (afterEvent.tv_usec - beforeFork.tv_usec > 1000000) {
        int nsec = (beforeFork.tv_usec - afterEvent.tv_usec) / 1000000;
        beforeFork.tv_usec += 1000000 * nsec;
        beforeFork.tv_sec -= nsec;
      }
      elapsed = (float)(afterEvent.tv_sec - beforeFork.tv_sec) + 
                (float)(afterEvent.tv_usec - beforeFork.tv_usec)/1000000.0;

      /* Meaningless since the muteafter variable is now an invalid copy */
      // releaseMuteafter(&myGlobals.hostsHashMuteafter);

      /* This is zero in the parent copy of the structure,
         make it non-zero here so we can tell later on  (BMS 2003-06)
       */
      myGlobals.childntoppid = getpid();

      xmlDebug(__FILE__, __LINE__, 2, "......fork()ed child is %d fork() took %.6f", myGlobals.childntoppid, elapsed);

      alarm(0); /* Cancel any pre-existing alarm call */

    } /* not debug */
#endif /* With fork() */

    // Remember: DO NOT sendHTTPHeader() - it confuses browsers...
    sendString("<?xml version=\"1.0\" ?>\n"
               "<!-- START dumpXML() -->\n");

    /* Now set up our basic protective environment ... something bad?  We just give up... */
    if ((siglongjmpReturnValue = setjmp(siglongjmpEnv)) != 0) {
      /* Return here on error ... (we'll override and get smarter below... */
#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
      /* Fork()ed ... nothing fancy - just die and let the OS cleanup */
      exit(0);
#else
      /* Not fork()ed ... restore handlers and return to caller */
      rc = sigaction(SIGSEGV, &xml_old_act_SEGV, NULL);
#ifdef XMLDUMP_DEBUG
      traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGSEGV,,) set %s(%d)", strerror(rc), rc);
#endif

      return(0);
#endif
    }

    xmlDebug(__FILE__, __LINE__, 2, "...creating error traps", "");

    /* Store this basic jump buffer to restore at the end of dumpXML() */
    memcpy(siglongjmpBasicEnv, siglongjmpEnv, sizeof(jmp_buf));

    xml_new_act.sa_flags=SA_RESTART|SA_SIGINFO;
    xml_new_act.sa_sigaction = xml_sighandler;
    sigemptyset(&xml_new_act.sa_mask);

    rc = sigaction(SIGSEGV, &xml_new_act, &xml_old_act_SEGV);
    xmlDebug(__FILE__, __LINE__, 3, "......sigaction(SIGSEGV,,) set %s(%d)", strerror(rc), rc);

//     rc = sigaction(SIGCHLD, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGCHLD,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGHUP, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGHUP,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGINT, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGINT,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGQUIT, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGQUIT,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGILL, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGILL,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGABRT, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGABRT,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGFPE, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGFPE,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGKILL, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGKILL,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGPIPE, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGPIPE,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGTERM, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGTERM,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGUSR1, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGUSR1,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
//     rc = sigaction(SIGUSR2, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGUSR2,,) set %s(%d)", strerror(rc), rc);
// #endif
// 
// #ifdef SIGCONT
//     rc = sigaction(SIGCONT, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGCONT,,) set %s(%d)", strerror(rc), rc);
// #endif
// #endif
// 
// #ifdef SIGSTOP
//     rc = sigaction(SIGSTOP, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGSTOP,,) set %s(%d)", strerror(rc), rc);
// #endif
// #endif
// 
// #ifdef SIGBUS
//     rc = sigaction(SIGBUS, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGBUS,,) set %s(%d)", strerror(rc), rc);
// #endif
// #endif
// 
// #ifdef SIGSYS
//     rc = sigaction(SIGSYS, &xml_new_act, NULL);
// #ifdef XMLDUMP_DEBUG
//     traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP_DEBUG: sigaction(SIGSYS,,) set %s(%d)", strerror(rc), rc);
// #endif
// #endif


    /* **********************************************************************************
     * Skip .xml name (we basically accept ANYTHING) to the options...
     *    dump.xml?a=b&c=d
     * ********************************************************************************** */
    urlOptions = strstr(url, "?");
    xmlDebug(__FILE__, __LINE__, 2, "...Parameters from url are '%s'", urlOptions);

    /* **********************************************************************************
     *   Setup the dtd URI
     * (we don't bother with gdome_di_createDocumentType 'cause it
     *  flat out doesn't work)
     */
/* TODO Schema? */
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s://%s:%d/%s",
                                   myGlobals.runningPref.webPort != 0 ? "http" :
                                                            (myGlobals.runningPref.sslPort != 0 ? "https" :
                                                                                      "file"),
                                   hostName,
                                   myGlobals.runningPref.webPort != 0 ? myGlobals.runningPref.webPort :
                                                            (myGlobals.runningPref.sslPort != 0 ? myGlobals.runningPref.sslPort :
                                                                                      0),
                                   CONST_XML_DTD_NAME);
    dtdURI = strdup(buf);

    /* **********************************************************************************
     * Get a DOMImplementation reference - does the startup for libxml, gdome et al
     * Then, create a new document with ntop_dump as root element
     *   and obtain a reference to the root.
     */
    domimpl = gdome_di_mkref();

    qualifiedName = gdome_str_mkref(CONST_XML_DOCTYPE_NAME);

    namespaceURI  = gdome_str_mkref(NULL);
    doc = gdome_di_createDocument(domimpl, namespaceURI, qualifiedName, NULL, &exc);
    if (namespaceURI != NULL)
        gdome_str_unref(namespaceURI);
    if (exc) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: createDocument: failed, Exception #%d", exc);
        gdome_str_unref(qualifiedName);
        gdome_di_unref (domimpl, &exc);
        return 1;
    }

    publicId      = gdome_str_mkref(NULL);
    systemId      = gdome_str_mkref(dtdURI);
    dt = gdome_di_createDocumentType(domimpl, qualifiedName, publicId, systemId, &exc);
    if (publicId != NULL)
        gdome_str_unref(publicId);
    if (systemId != NULL)
        gdome_str_unref(systemId);
    gdome_str_unref(qualifiedName);
    if (exc) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: createDocumentType: failed, Exception #%d", exc);
        gdome_di_unref (domimpl, &exc);
        return 1;
    }
    /* From here on, we have a structure, so we have to continue on to free everything */
    root = gdome_doc_documentElement(doc, &exc);
    if (exc) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: documentElement(root): failed, Exception #%d", exc);
        rc=exc;
    }

/* IGNORE FOR NOW
    result = gdome_doc_appendChild(doc, (GdomeNode *)dt, &exc);
    if (exc) {
        traceEvent_forked(CONST_TRACE_ERROR, "XMLDUMP: appendChild[dt]: failed, Exception #%d", exc);
        rc=exe;
    }
*/

    /* **********************************************************************************
     *   We always dump the header and command line -- the rest is controlled by flags...
     */

    sendString("<!-- ...Create XML tree -->\n");

    if (rc == 0) {
        sendString("<!-- ......Creating header -->\n");
        el = dumpXML_createHeader();
        if (el == NULL) {
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_createHeader() is NULL");
            rc = 1;
        }
    }

    if ( (rc == 0) && (dumpConfiguration == TRUE) ) {
        sendString("<!-- ......Dumping configuration -->\n");
        el = dumpXML_configuration();
        if (el == NULL) {
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_configuration() is NULL");
            rc = 1;
        }
    }

    if ( (rc == 0) && (dumpStatistics == TRUE) ) {
        sendString("<!-- ......Dumping statistics -->\n");
        el = dumpXML_statistics();
        if (el == NULL) {
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_statistics() is NULL");
            rc = 1;
        }
    }

    if ( (rc == 0) && (dumpInternals == TRUE) ) {
        sendString("<!-- ......Dumping internals -->\n");
        el = dumpXML_internals();
        if (el == NULL) {
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_internals() is NULL");
            rc = 1;
        }
    }
    if ( (rc == 0) && (dumpHosts == TRUE) ) {
        sendString("<!-- ......Dumping hosts (will take a while) -->\n");
        el = dumpXML_hosts();
        if (el == NULL) {
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_hosts() is NULL");
            rc = 1;
        }
    }

    if ( (rc == 0) && (dumpInterfaces == TRUE) ) {
        sendString("<!-- ......Dumping interfaces -->\n");
        el = dumpXML_interfaces();
        if (el == NULL) {
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_interfaces() is NULL");
            rc = 1;
        }
    }

    sendString("<!-- ...XML created -->\n");

    /* ********************************************************************************** */

    /* walk the created document and write it out */
    if (rc == 0) {
        sendString("<!-- ...Write XML file -->\n");
        rc = dumpXML_writeout();
        if (rc != 0)
            traceEvent_forked(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_writeout() is %d", rc);
    }

    sendString("<!-- END   dumpXML() -->\n");

    /* ********************************************************************************** */

    /* free the document structure and the DOMImplementation */
        /* TODO Do we need to free dt ? */
    gdome_di_freeDoc (domimpl, doc, &exc);
    gdome_di_unref (domimpl, &exc);

    /* ********************************************************************************** */

    xmlDebug(__FILE__, __LINE__, 2, "...Finished with dumpXML rc %s(%d) SIGSEGV count(%d)",
                                    strerror(rc), rc,
                                    segv_count);

    /* Restore the basic jump buffer  */
    memcpy(siglongjmpEnv, siglongjmpBasicEnv, sizeof(jmp_buf));

#if defined(PARM_FORK_CHILD_PROCESS) && (!defined(WIN32))
    gettimeofday(&afterEvent, NULL);

    if (afterEvent.tv_usec < beforeFork.tv_usec) {
      int nsec = (beforeFork.tv_usec - afterEvent.tv_usec) / 1000000 + 1;
      beforeFork.tv_usec -= 1000000 * nsec;
      beforeFork.tv_sec += nsec;
    }
    if (afterEvent.tv_usec - beforeFork.tv_usec > 1000000) {
      int nsec = (beforeFork.tv_usec - afterEvent.tv_usec) / 1000000;
      beforeFork.tv_usec += 1000000 * nsec;
      beforeFork.tv_sec -= nsec;
    }
    elapsed = (float)(afterEvent.tv_sec - beforeFork.tv_sec) + 
              (float)(afterEvent.tv_usec - beforeFork.tv_usec)/1000000.0;

    xmlDebug(__FILE__, __LINE__, 1, "...Page creation took %.6f", elapsed);
#endif

    xmlDebug(__FILE__, __LINE__, 1, "END   dumpXML()", "");

    return 0;
}
#endif /* MAKE_WITH_XMLDUMP */

/* ************************************************** */

static void traceEvent_forked(int eventTraceLevel, char* file,
                int line, char * format, ...) {
  va_list va_ap;

#ifdef WIN32
    if(isNtopAservice) return;
#endif

  inTraceEventForked=1;

  va_start (va_ap, format);

  if(eventTraceLevel <= myGlobals.runningPref.traceLevel) {
    time_t theTime = time(NULL);
    struct tm t;
    char bufF[LEN_GENERAL_WORK_BUFFER];
    char bufMsg[LEN_GENERAL_WORK_BUFFER];
    char bufMsgID[LEN_MEDIUM_WORK_BUFFER];
    char bufLineID[LEN_MEDIUM_WORK_BUFFER];

    int beginFileIdx=0;
    char *mFile = NULL;

    /* If ntop is a Win32 service, we're done - we don't (yet) write to the
     * windows event logs and there's no console...
     */
    /* First we prepare the various fields */
  
    /* The file/line or 'MSGID' tag, depends on logExtra */
    memset(bufMsgID, 0, sizeof(bufMsgID));

    if(myGlobals.runningPref.traceLevel > CONST_NOISY_TRACE_LEVEL) {
      mFile = strdup(file);

      if(mFile) {
        for(beginFileIdx=strlen(mFile)-1; beginFileIdx>0; beginFileIdx--) {
          if(mFile[beginFileIdx] == '.') mFile[beginFileIdx] = '\0'; /* Strip off .c */
#if defined(WIN32)
          if(mFile[beginFileIdx-1] == '\\') break;  /* Start after \ (Win32)  */
#else
          if(mFile[beginFileIdx-1] == '/') break;   /* Start after / (!Win32) */
#endif
        }

        if(myGlobals.runningPref.traceLevel >= CONST_DETAIL_TRACE_LEVEL) {
          unsigned int messageid = 0;
          int i;

          safe_snprintf(__FILE__, __LINE__, bufLineID, sizeof(bufLineID), "[%s:%d] ", &mFile[beginFileIdx], line);

          /* Hash the message format into an id */
          for (i=0; i<=strlen(format); i++) {
            messageid = (messageid << 1) ^ max(0,format[i]-32);
          }

          /* 1st chars of file name for uniqueness */
          messageid += (file[0]-32) * 256 + file[1]-32;
          safe_snprintf(__FILE__, __LINE__, bufMsgID, sizeof(bufMsgID), "[MSGID%07d]", (messageid & 0x8fffff));
        }

        free(mFile);
      }
    }

    /* Now we use the variable functions to 'print' the user's message */
    memset(bufMsg, 0, sizeof(bufMsg));
    vsnprintf(bufMsg, sizeof(bufMsg), format, va_ap);
    /* Strip a trailing return from bufMsg */
    if(bufMsg[strlen(bufMsg)-1] == '\n')
      bufMsg[strlen(bufMsg)-1] = 0;

    /* Second we prepare the complete log message into buf
     */
    memset(bufF, 0, sizeof(bufF));
    safe_snprintf(__FILE__, __LINE__, bufF, sizeof(bufF), "%s %s%s%s",
                  (myGlobals.runningPref.traceLevel >= CONST_DETAIL_TRACE_LEVEL) ? bufMsgID : "",
                  (myGlobals.runningPref.traceLevel > CONST_DETAIL_TRACE_LEVEL) ? bufLineID : "",
                  eventTraceLevel == CONST_FATALERROR_TRACE_LEVEL  ? "**FATAL_ERROR** " :
                  eventTraceLevel == CONST_ERROR_TRACE_LEVEL   ? "**ERROR** " :
                  eventTraceLevel == CONST_WARNING_TRACE_LEVEL ? "**WARNING** " : "",
                  bufMsg);

    /* Finished preparing message fields */

    /* No logView */

    /* SYSLOG and set */
    openlog("ntop", LOG_PID, myGlobals.runningPref.useSyslog);

    /* syslog(..) call fix courtesy of Peter Suschlik <peter@zilium.de> */
#ifdef MAKE_WITH_LOG_XXXXXX
    switch(myGlobals.runningPref.traceLevel) {
    case CONST_FATALERROR_TRACE_LEVEL:
    case CONST_ERROR_TRACE_LEVEL:
      syslog(LOG_ERR, "%s", bufF);
      break;
    case CONST_WARNING_TRACE_LEVEL:
      syslog(LOG_WARNING, "%s", bufF);
      break;
    case CONST_ALWAYSDISPLAY_TRACE_LEVEL:
      syslog(LOG_NOTICE, "%s", bufF);
      break;
    default:
      syslog(LOG_INFO, "%s", bufF);
      break;
    }
#else
    syslog(LOG_ERR, "%s", bufF);
#endif
    closelog();
  }

  va_end (va_ap);

  inTraceEventForked=0;

}

#endif /* MAKE_WITH_XMLDUMP */

/* ************************************************** */
