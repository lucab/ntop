/*
 *  Copyright (C) 2002 Luca Deri <deri@ntop.org>
 *                     Burton M. Strausss III <Burton@ntopsupport.com>
 *
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
   A note:  We don't output the data from the structure in the exact same
            organization as it really is (myGlobals).  Instead we break it
            up into the logical organization that should make the data of use
            to outside manipulation...

        node name        - flag           - description

        ntop_dump_header - always present - critical info about the xml file.
        version_c_header - version=       - information about how ntop was built/compiled
        invoke           - invoke=        - information about how ntop was invoked


 */

/*

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
      traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_xyx\n");
  #endif

      #include "xml_s_xyx.inc"

  #ifdef XMLDUMP_DEBUG
      traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_xyx\n");
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

#include "ntop.h"
#include <stdarg.h>

#ifdef MAKE_WITH_XMLDUMP

#include <glibconfig.h>
#include <gdome.h>

/* dumpXML.c globals... */	
GdomeDOMImplementation *domimpl;
GdomeDocument *doc;
GdomeElement *root;
char *dtdURI;

char *iso8601timespec="%Y-%m-%dT%H:%M:%S";

char buf[LEN_GENERAL_WORK_BUFFER],
     buf2[LEN_MEDIUM_WORK_BUFFER],
     buf3[LEN_MEDIUM_WORK_BUFFER],
     buf4[LEN_SMALL_WORK_BUFFER],
     buf5[LEN_SMALL_WORK_BUFFER],
     buf6[LEN_SMALL_WORK_BUFFER],
     buf7[LEN_SMALL_WORK_BUFFER],
     buf8[LEN_SMALL_WORK_BUFFER];

struct sigaction xml_new_act, xml_old_act;
volatile sig_atomic_t segv_count = 0;


/* internal functions */
GdomeElement * _newxml(char * filename, int linenum, 
                       GdomeNodeType nodetype, 
                       GdomeElement * parent,
                       char * nodename,
                       GdomeException exc,
                       ...) {
    int rc=0;
    GdomeElement *temp_el;
    GdomeDOMString *temp_nodename, *temp_attrname, *temp_attrvalue;
    char *attrname, *attrvalue;

    va_list ap;

#if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: START newxml() at %d(%s)\n", linenum, filename);
#endif

    switch (nodetype) {
	case GDOME_ELEMENT_NODE:
            if (nodename == NULL) {
                traceEvent(CONST_TRACE_ERROR,
                           "XMLDUMP_DEBUG:       newxml() at %d(%s) nodename NULL\n",
                           linenum, filename);
                temp_nodename = gdome_str_mkref("null");
            } else {
                temp_nodename = gdome_str_mkref(nodename);
            }
            temp_el = gdome_doc_createElement (doc, temp_nodename, &exc);
            if (exc) {
                traceEvent(CONST_TRACE_ERROR, 
                           "XMLDUMP:      newxml() at %d(%s), createElement failed, Exception #%d\n", 
                           linenum, 
                           filename, 
                           &exc);
                rc=(int) exc;
            }
            if (temp_nodename != NULL) 
                gdome_str_unref(temp_nodename);
            break;
        default:
            temp_el=NULL;
            rc=1;
            break;
    }

    /* set attributes */
    if (rc == 0) {

        va_start(ap, exc);

        attrname=va_arg(ap, char *);

        while ( (attrname != NULL) && (strcmp(attrname, "__sentinel__") != 0) ) {

            attrvalue=va_arg(ap, char *);
            if ( (attrvalue != NULL) && 
                 (strcmp(attrvalue, "__sentinel__") == 0) ) {
#if (XMLDUMP_DEBUG >= 2)
                traceEvent(CONST_TRACE_INFO, 
                           "XMLDUMP_DEBUG:       newxml() at %d(%s) attrname __sentinel__\n", 
                           linenum, filename);
#endif
                break;
            }
            if ( (attrvalue != NULL) && 
                 (strcmp(attrname, "description") == 0) && 
                 (strcmp(attrvalue, "") == 0) ) {
#if (XMLDUMP_DEBUG >= 2)
                traceEvent(CONST_TRACE_INFO, 
                           "XMLDUMP_DEBUG:       newxml() at %d(%s) skip null description\n", 
                           linenum, filename);
#endif
                break;
            }

            switch (nodetype) {
	        case GDOME_ELEMENT_NODE:
                    temp_attrname = gdome_str_mkref (attrname);

                    if (attrvalue == NULL) {
                        temp_attrvalue = gdome_str_mkref ("(null)");
                    } else {
                        temp_attrvalue = gdome_str_mkref (attrvalue);
                    }

                    gdome_el_setAttribute (temp_el, temp_attrname, temp_attrvalue, &exc);

                    if (exc) {
                        traceEvent(CONST_TRACE_ERROR,
                                   "XMLDUMP:      newxml() at %d(%s), el_setAttribute failed, Exception #%d\n",
                                   linenum,
                                   filename,
                                   exc);
                        rc=(int) exc;
                    }
                    gdome_str_unref(temp_attrname);
                    gdome_str_unref(temp_attrvalue);
                    break;
                default:
                    break;
            }

            attrname=va_arg(ap, char *);
        }

        va_end(ap);
    }

    /* append to parent */
    if ( (rc == 0) && (parent != NULL) ) {
        switch (nodetype) {
            case GDOME_ELEMENT_NODE:
                gdome_el_appendChild (parent, (GdomeNode *)temp_el, &exc);
                if (exc) {
                    traceEvent(CONST_TRACE_ERROR,
                               "XMLDUMP:      newxml() at %d(%s), el_appendChild failed, Exception #%d\n",
                               linenum,
                               filename,
                               exc);
                    rc=(int) exc;
                }
                break;
            default:
                break;
        }
    }

#if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: END   newxml() at %d(%s) rc=%d\n", linenum, filename, rc);
#endif

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

#define newxmlna(nodetype, parent, name) \
        _newxml(__FILE__, __LINE__, nodetype, parent, name, exc, "__sentinel__")

#define newxml(nodetype, parent, name, ... ) \
        _newxml(__FILE__, __LINE__, nodetype, parent, name, exc, __VA_ARGS__, "__sentinel__")

#define newxml_empty(parent, name, description) \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "description", description)

#define newxml_simplenoyes(parent, name, booleanvar, description) \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "value", booleanvar == 0 ? "No" : "Yes", \
                               "description", description)

#define newxml_simplestring(parent, name, stringvar, description) \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "value", stringvar, \
                               "description", description)

#define newxml_namedstring(parent, name, stringvar, description, stringname) \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               stringname, stringvar, \
                               "description", description)

/* WARNING: The following DO NOT return a value! */

#define newxml_simplehex(parent, name, hexvar, description) {\
    if (snprintf(buf, sizeof(buf), "0x%x", hexvar) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "value", buf, \
                               "description", description); \
}

#define newxml_fd_set(parent, name, hexvar, description) \
    newxml_simplehex(parent, name, hexvar, description)

#define newxml_simplestringindex(parent, name, stringvar, description, index) { \
    if (snprintf(buf, sizeof(buf), "%d", index) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "index", buf, \
                               "value", stringvar, \
                               "description", description); \
}

#define newxml_simplenumeric(parent, name, numericvar, description, format) {\
    if (snprintf(buf, sizeof(buf), format, numericvar) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "value", buf, \
                               "description", description); \
}

#define newxml_namednumeric(parent, name, numericvar, description, format, fieldname) { \
    if (snprintf(buf, sizeof(buf), format, numericvar) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               fieldname, buf, \
                               "description", description); \
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                              Forward...                                       */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                 Complex "types" first - usually hand coded below...           */
/*                                                                               */
/*             (note input is NOT a pointer!)                                    */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                 Then structures used via pointers                             */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

GdomeElement * newxml_dhcpstats(GdomeElement * parent,
                       char * nodename,
                       DHCPStats * input,
                       char * description);

GdomeElement * newxml_domainstats(GdomeElement * parent,
                       char * nodename,               
                       DomainStats * input,           
                       char * description); 

GdomeElement * newxml_elementhash(GdomeElement * parent,
                       char * nodename,
                       ElementHash * input,
                       char * description);

GdomeElement * newxml_filelist(GdomeElement * parent,
                       char * nodename,
                       FileList * input,
                       char * description);

GdomeElement * newxml_hashlist(GdomeElement * parent,
                       char * nodename,
                       HashList * input,
                       char * description);

GdomeElement * newxml_hosttraffic(GdomeElement * parent,
                       char * nodename,
                       HostTraffic * input,
                       char * description);

GdomeElement * newxml_icmphostinfo(GdomeElement * parent,
                       char * nodename,
                       IcmpHostInfo * input,
                       char * description);

GdomeElement * newxml_ipsession(GdomeElement * parent,
                       char * nodename,
                       IPSession * input,
                       char * description);

GdomeElement * newxml_noniptraffic(GdomeElement * parent,
                       char * nodename,
                       NonIPTraffic * input,
                       char * description);

GdomeElement * newxml_ntopinterface(GdomeElement * parent,
                       char * nodename,
                       NtopInterface * input,
                       char * description);

GdomeElement * newxml_packetstats(GdomeElement * parent,
                       char * nodename,
                       PacketStats * input,
                       char * description);

GdomeElement * newxml_plugininfo(GdomeElement * parent,
                       char * nodename,
                       PluginInfo * input,
                       char * description);

GdomeElement * newxml_portcounter(GdomeElement * parent,
                       char * nodename,
                       PortCounter * input,
                       char * description);

GdomeElement * newxml_portmapper(GdomeElement * parent,
                       char * nodename,
                       PortMapper * input,
                       char * description);

GdomeElement * newxml_portusage(GdomeElement * parent,
                       char * nodename,
                       PortUsage * input,
                       char * description);

GdomeElement * newxml_protocolinfo(GdomeElement * parent,
                       char * nodename,
                       ProtocolInfo * input,
                       char * description);

GdomeElement * newxml_prototrafficinfo(GdomeElement * parent,        
                       char * nodename,
                       ProtoTrafficInfo * input,
                       char * description);

#ifdef CFG_MULTITHREADED
GdomeElement * newxml_pthreadmutex(GdomeElement * parent,
                       char * nodename,
                       PthreadMutex * input,
                       char * description);
#endif

GdomeElement * newxml_routingcounter(GdomeElement * parent,
                       char * nodename,
                       RoutingCounter * input,
                       char * description);

GdomeElement * newxml_securityhostprobes(GdomeElement * parent,
                       char * nodename,
                       SecurityHostProbes * input,
                       char * description);

GdomeElement * newxml_serviceentry(GdomeElement * parent,
                       char * nodename,
                       ServiceEntry * input,
                       char * description);

GdomeElement * newxml_servicestats(GdomeElement * parent,
                       char * nodename,
                       ServiceStats * input,
                       char * description);

GdomeElement * newxml_simpleprototrafficinfo(GdomeElement * parent,
                       char * nodename,
                       SimpleProtoTrafficInfo * input,
                       char * description);

GdomeElement * newxml_ssl_connection(GdomeElement * parent,
                       char * nodename,
                       SSL_connection * input,
                       char * description);

GdomeElement * newxml_trafficdistribution(GdomeElement * parent,
                       char * nodename,
                       TrafficDistribution * input,
                       char * description);

GdomeElement * newxml_trafficentry(GdomeElement * parent,
                       char * nodename,
                       TrafficEntry * input,
                       char * description);

GdomeElement * newxml_thptentry(GdomeElement * parent,
                       char * nodename,
                       ThptEntry * input,
                       char * description);

GdomeElement * newxml_ttlstats(GdomeElement * parent,
                       char * nodename,
                       TTLstats * input,
                       char * description);

GdomeElement * newxml_usagecounter(GdomeElement * parent,
                       char * nodename,
                       UsageCounter * input,
                       char * description);

GdomeElement * newxml_userlist(GdomeElement * parent,
                       char * nodename,
                       UserList * input,
                       char * description);

GdomeElement * newxml_virtualhostlist(GdomeElement * parent,
                       char * nodename,
                       VirtualHostList * input,
                       char * description);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                              Special types                                    */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Please keep them in alphabetic order for ease of finding them...              */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define newxml_hostserial(parent, name, hostserial_var, description) \
        newxml_simplenumeric(parent, name, hostserial_var, description, "%u")

#define newxml_hostserial_index(parent, name, hostserial_var, index_var, description) \
    if (snprintf(buf, sizeof(buf), "%u", hostserial_var) < 0) \
        BufferTooShort(); \
    if (snprintf(buf2, sizeof(buf2), "%d", index_var) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, \
                               "index", buf2, \
                               "value", buf, \
                               "description", description); \
}

#define newxml_in_addr(parent, name, in_addr_var, description) { \
    if (snprintf(buf, sizeof(buf), "%d.%d.%d.%d", \
                 (int) ((in_addr_var.s_addr >> 24) & 0xff), \
                 (int) ((in_addr_var.s_addr >> 16) & 0xff), \
                 (int) ((in_addr_var.s_addr >>  8) & 0xff), \
                 (int) ((in_addr_var.s_addr >>  0) & 0xff)) < 0) \
        BufferTooShort(); \
    if (snprintf(buf2, sizeof(buf2), "%u", in_addr_var.s_addr) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf2, "interpreted", buf, "description", description); \
}

#define newxml_time_t(parent, name, time_t_var, description) { \
    memcpy(&buf, ctime(&time_t_var), sizeof("Wed Jun 30 21:49:08 1993\n")-1); \
    buf[sizeof("Wed Jun 30 21:49:08 1993\n")-2] = '\0'; \
    if (snprintf(buf2, sizeof(buf2), "%d", time_t_var) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf2, "interpreted", buf, "description", description); \
}

#define newxml_timeval(parent, name, timeval_var, description) { \
    memcpy(&buf, ctime(&timeval_var.tv_sec), sizeof("Wed Jun 30 21:49:08 1993\n")-1); \
    buf[sizeof("Wed Jun 30 21:49:08 1993\n")-2] = '\0'; \
    if (snprintf(buf2, sizeof(buf2), "%s 0.%06d", buf, timeval_var.tv_usec) < 0) \
        BufferTooShort(); \
    if (snprintf(buf3, sizeof(buf3), "%d.%06d", timeval_var.tv_sec, timeval_var.tv_usec) < 0) \
        BufferTooShort(); \
    newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf3, "interpreted", buf2, "description", description); \
}

#ifdef WIN32
    #define newxml_counter(parent, name, counter_var, description) { \
        if (snprintf(buf, sizeof(buf), "%f", counter_var) < 0) \
            BufferTooShort(); \
        newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf, "description", description); \
    }
    #define newxml_trafficcounter(parent, name, trafficcounter_var, description) { \
        if (snprintf(buf, sizeof(buf), "%f", trafficcounter_var.value) < 0) \
            BufferTooShort(); \
        newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf, \
               "modified", trafficcounter_var.modified ? "true" : "false", \
               "description", description); \
    }
#else
    #define newxml_counter(parent, name, counter_var, description) { \
        if (snprintf(buf, sizeof(buf), "%llu", counter_var) < 0) \
            BufferTooShort(); \
        newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf, "description", description); \
    }
    #define newxml_trafficcounter(parent, name, trafficcounter_var, description) { \
        if (snprintf(buf, sizeof(buf), "%llu", trafficcounter_var.value) < 0) \
            BufferTooShort(); \
        newxml(GDOME_ELEMENT_NODE, parent, name, "value", buf, \
               "modified", trafficcounter_var.modified ? "true" : "false", \
               "description", description); \
    }
#endif


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*                              structs                                          */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Please keep them in alphabetic order for ease of finding them...              */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

GdomeElement * newxml_dhcpstats(GdomeElement * parent,
                       char * nodename,
                       DHCPStats * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_dhcpstats\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_dhcpstats.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_dhcpstats\n");
#endif

    return elWork;
}

GdomeElement * newxml_domainstats(GdomeElement * parent,
                       char * nodename,               
                       DomainStats * input,           
                       char * description) {          

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_domainstats\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_domainstats.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_domainstats\n");
#endif

    return elWork;
}

GdomeElement * newxml_elementhash(GdomeElement * parent,
                       char * nodename,
                       ElementHash * input,
                       char * description) {

    GdomeElement *elWork, *elWork2, *elWork3;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_elementhash\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_elementhash.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_elementhash\n");
#endif

    return elWork;
}

GdomeElement * newxml_filelist(GdomeElement * parent,
                       char * nodename,
                       FileList * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_filelist\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_filelist.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_filelist\n");
#endif

    return elWork;
}

GdomeElement * newxml_hashlist(GdomeElement * parent,
                       char * nodename,
                       HashList * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_hashlist\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_hashlist.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_hashlist\n");
#endif

    return elWork;
}

GdomeElement * newxml_hosttraffic(GdomeElement * parent,
                       char * nodename,
                       HostTraffic * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_hosttraffic\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_hosttraffic.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_hosttraffic\n");
#endif

    return elWork;
}

GdomeElement * newxml_icmphostinfo(GdomeElement * parent,
                       char * nodename,
                       IcmpHostInfo * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_icmphostinfo\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_icmphostinfo.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_icmphostinfo\n");
#endif

    return elWork;
}

GdomeElement * newxml_ipsession(GdomeElement * parent,
                       char * nodename,
                       IPSession * input,
                       char * description);

GdomeElement * newxml_ipsession(GdomeElement * parent,
                       char * nodename,
                       IPSession * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_ipsession\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_ipsession.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_ipsession\n");
#endif

    return elWork;
}

GdomeElement * newxml_noniptraffic(GdomeElement * parent,
                       char * nodename,
                       NonIPTraffic * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_noniptraffic\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_noniptraffic.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_noniptraffic\n");
#endif

    return elWork;
}

GdomeElement * newxml_ntopinterface(GdomeElement * parent,
                       char * nodename,
                       NtopInterface * input,
                       char * description) {

    GdomeException exc;
    GdomeElement *elWork, *elWork2, *elWork3;

#if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_ntopinterface\n");
#endif

    #include "xml_s_ntopinterface.inc"

#if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_ntopinterface\n");
#endif

    return elWork;
}

GdomeElement * newxml_packetstats(GdomeElement * parent,
                       char * nodename,
                       PacketStats * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_packetstats\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_packetstats.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_packetstats\n");
#endif

    return elWork;
}

GdomeElement * newxml_plugininfo(GdomeElement * parent,
                       char * nodename,
                       PluginInfo * input,
                       char * description) {

    GdomeException exc;
    GdomeElement *elWork;

#if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_plugininfo\n");
#endif

    /* #include "xml_s_plugininfo.inc" */

#if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_plugininfo\n");
#endif

    return elWork;
}

GdomeElement * newxml_portcounter(GdomeElement * parent,
                       char * nodename,
                       PortCounter * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_portcounter\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_portcounter.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_portcounter\n");
#endif

    return elWork;
}

GdomeElement * newxml_portmapper(GdomeElement * parent,
                       char * nodename,
                       PortMapper * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_portmapper\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_portmapper.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_portmapper\n");
#endif

    return elWork;
}

GdomeElement * newxml_portusage(GdomeElement * parent,
                       char * nodename,
                       PortUsage * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_portusage\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_portusage.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_portusage\n");
#endif

    return elWork;
}

GdomeElement * newxml_protocolinfo(GdomeElement * parent,
                       char * nodename,
                       ProtocolInfo * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_protocolinfo\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_protocolinfo.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_protocolinfo\n");
#endif

    return elWork;
}

GdomeElement * newxml_prototrafficinfo(GdomeElement * parent,
                       char * nodename,
                       ProtoTrafficInfo * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_prototrafficinfo\n");
#endif                 

    /* Insert the generated block of code */
        /* #include "xml_s_prototrafficinfo.inc" */
                       
#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_prototrafficinfo\n");
#endif

    return elWork;
}

#ifdef CFG_MULTITHREADED
GdomeElement * newxml_pthreadmutex(GdomeElement * parent,
                       char * nodename,
                       PthreadMutex * input,
                       char * description) {

    GdomeException exc;
    GdomeElement *elWork;

 #if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_pthreadmutex\n");
 #endif

    /* #include "xml_s_pthreadmutex.inc" */

 #if (XMLDUMP_DEBUG >= 3)
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_pthreadmutex\n");
 #endif

    return elWork;
}
#endif

GdomeElement * newxml_routingcounter(GdomeElement * parent,
                       char * nodename,
                       RoutingCounter * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_routingcounter\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_routingcounter.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_routingcounter\n");
#endif

    return elWork;
}

GdomeElement * newxml_securityhostprobes(GdomeElement * parent,
                       char * nodename,
                       SecurityHostProbes * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_securityhostprobes\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_securityhostprobes.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_securityhostprobes\n");
#endif

    return elWork;
}

GdomeElement * newxml_serviceentry(GdomeElement * parent,
                       char * nodename,
                       ServiceEntry * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_serviceentry\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_serviceentry.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_serviceentry\n");
#endif

    return elWork;
}

GdomeElement * newxml_servicestats(GdomeElement * parent,
                       char * nodename,
                       ServiceStats * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_servicestats\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_servicestats.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_servicestats\n");
#endif

    return elWork;
}

GdomeElement * newxml_simpleprototrafficinfo(GdomeElement * parent,
                       char * nodename,
                       SimpleProtoTrafficInfo * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_simpleprototrafficinfo\n");
#endif

    /* Insert the generated block of code */
        #include "xml_s_simpleprototrafficinfo.inc"

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_simpleprototrafficinfo\n");
#endif

    return elWork;
}

GdomeElement * newxml_ssl_connection(GdomeElement * parent,
                       char * nodename,
                       SSL_connection * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_ssl_connection\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_ssl_connection.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_ssl_connection\n");
#endif

    return elWork;
}

GdomeElement * newxml_trafficentry(GdomeElement * parent,
                       char * nodename,
                       TrafficEntry * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_trafficentry\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_trafficentry.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_trafficentry\n");
#endif

    return elWork;
}

GdomeElement * newxml_thptentry(GdomeElement * parent,
                       char * nodename,
                       ThptEntry * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_thptentry\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_thptentry.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_thptentry\n");
#endif

    return elWork;
}

GdomeElement * newxml_trafficdistribution(GdomeElement * parent,
                       char * nodename,
                       TrafficDistribution * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_trafficdistribution\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_trafficdistribution.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_trafficdistribution\n");
#endif

    return elWork;
}

GdomeElement * newxml_ttlstats(GdomeElement * parent,
                       char * nodename,
                       TTLstats * input,
                       char * description) {

    GdomeElement *elWork;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_ttlstats\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_ttlstats.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_ttlstats\n");
#endif

    return elWork;
}

GdomeElement * newxml_usagecounter(GdomeElement * parent,
                       char * nodename,
                       UsageCounter * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_usagecounter\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_usagecounter.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_usagecounter\n");
#endif

    return elWork;
}

GdomeElement * newxml_userlist(GdomeElement * parent,
                       char * nodename,
                       UserList * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_userlist\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_userlist.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_userlist\n");
#endif

    return elWork;
}

GdomeElement * newxml_virtualhostlist(GdomeElement * parent,
                       char * nodename,
                       VirtualHostList * input,
                       char * description) {

    GdomeElement *elWork, *elWork2;
    GdomeException exc;

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting newxml_virtualhostlist\n");
#endif

    /* Insert the generated block of code */
        /* #include "xml_s_virtualhostlist.inc" */

#if (XMLDUMP_DEBUG >= 3)
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending newxml_virtualhostlist\n");
#endif

    return elWork;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

GdomeElement * dumpXML_createHeader(int dumpToFile, int effectiveDumpToFile) {

    GdomeElement *elHeader;
    GdomeException exc;
    time_t now;
    int stableDump;

#ifdef MAKE_WITH_FORK_COPYONWRITE
    stableDump    = TRUE /* COPYONWRITE means we're dumping from an unchanging copy */;
#else
    if (dumpToFile == 1)
        stableDump    = TRUE /* During shutdown, it's stable */;
    else
        stableDump    = FALSE;
#endif

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML_createHeader\n");
#endif

    now  = time(NULL);

    if (snprintf(buf, sizeof(buf), "%s", 
        dumpToFile == 1 ? "shutdown" : 
                (effectiveDumpToFile == 1 ? "snapshot" : "interactive")) < 0)
        BufferTooShort();

    elHeader = newxml(GDOME_ELEMENT_NODE, root, "ntop_dump_header",
                                                "date",          formatTime(&now, 0),
                                                "hostName",      myGlobals.hostName,
                                                "xml_version",   CONST_XML_VERSION,
                                                "file_version",  buf,
                                                "stable",        stableDump == TRUE ? "Yes" : "No");

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending dumpXML_createHeader\n");
#endif

    return elHeader;
}

GdomeElement * dumpXML_versioncHeader(void) {

    GdomeElement *elHeader;
    GdomeException exc;

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML_versioncHeader\n");
#endif

    elHeader = newxmlna(GDOME_ELEMENT_NODE, root, "version_c_header");
    /* Parameters from version.c */
    newxml_simplestring(elHeader, "ntop_version",       version,               "");
    newxml_simplestring(elHeader, "buildDate",          buildDate,             "");
    newxml_simplestring(elHeader, "author",             author,                "");
    newxml_simplestring(elHeader, "osName",             osName,                "");
    newxml_simplestring(elHeader, "dotconfigure",       configure_parameters,  "");
    newxml_simplestring(elHeader, "host_system_type",   host_system_type,      "");
    newxml_simplestring(elHeader, "target_system_type", target_system_type,    "");
    newxml_simplestring(elHeader, "compiler_cflags",    compiler_cflags,       "");
    newxml_simplestring(elHeader, "include_path",       include_path,          "");
    newxml_simplestring(elHeader, "system_libs",        system_libs,           "");
    newxml_simplestring(elHeader, "install_path",       install_path,          "");
#ifdef MAKE_WITH_I18N
    newxml_simplestring(elHeader, "locale_dir",         locale_dir,            "");
#endif

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending dumpXML_versioncHeader\n");
#endif

    return elHeader;
}

GdomeElement * dumpXML_invoke(void) {
    int rc=0, i;
    GdomeException exc;
    GdomeElement *elInvoke, *elExecenv, *elArg, *elPaths, *elOptions, *elProtocols;

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML_invoke\n");
#endif

    #include "xml_g_invoke.inc"

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending dumpXML_invoke\n");
#endif

    return elInvoke;
}

#ifdef CFG_MULTITHREADED
GdomeElement * dumpXML_multithread(GdomeElement * parent) {
    int rc=0;
    GdomeException exc;
    GdomeElement *elMultithread, *elMutexes;

 #ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML_multithread\n");
 #endif

    #include "xml_g_multithread.inc"

 #ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending dumpXML_multithread\n");
 #endif

    return elMultithread;
}
#endif

GdomeElement * dumpXML_interfaces(void) {
    GdomeException exc;
    GdomeElement *elInterfaces, *elWork;

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML_interfaces\n");
#endif

    #include "xml_g_intf.inc"

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending dumpXML_interfaces\n");
#endif

    return elInterfaces;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

int dumpXML_writeout(int dumpToFile, int effectiveDumpToFile) {

    GdomeDocumentType* dt;
    GdomeException exc;
    GdomeDOMString *name, *systemId;

    FILE *fdTemp, *fdOut;
    int len, rc;
    char tmpFileName[NAME_MAX];
    char tmpStr[512];
    char * doctypeHeader;

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML_writeout (%d/%d)\n",
               dumpToFile,
               effectiveDumpToFile);
#endif

    /* Output the DOM tree 
     *
     *    What's special here is:
     *
     *     - the handling of the 1st block - we may have to force the doctype line!
     *
     *     - We may output to the http client sendString/sendStringLen or to a file...
     *
     */

    /* Figure out if we are echoing to a file, and if so, which one
     *   If parameter dumpToFile is set, the request came from ntop during shutdown and we
     *                dump to xmlfileout
     *   If effectiveDumpToFile is set (and not dumpToFile), then the request was from
     *                the user via duml.xml?tofile=yes  and we dump to xmlfilesnap.
     *    We deliberately reuse the file for the xml snapshot to prevent a DOS attack
     *    We cleverly force effectiveDumpToFile to initialize to dumpToFile, so that we can
     *       use it as a general test after we open the correct file!
     */
    if (dumpToFile == 1) {
        if (myGlobals.xmlFileOut == NULL) {
            traceEvent(CONST_TRACE_WARNING, "XMLDUMP: xml write to unspecified 'out' file skipped...\n");
            return 0;
        }
#ifdef XMLDUMP_DEBUG
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Opening output file (out), '%s'\n", 
                               myGlobals.xmlFileOut);
#endif
        fdOut = fopen(myGlobals.xmlFileOut, "wb");
    } else if (effectiveDumpToFile == 1) {
        if (myGlobals.xmlFileSnap == NULL) {
            traceEvent(CONST_TRACE_WARNING, "XMLDUMP: xml write to unspecified 'snap' file skipped...\n");
            sendString("<?xml version=\"1.0\" ?>\n"
                       "<ntop_dump>\n"
                       "<ntop_dump_tofile status=\"failed\" \n"
                           "cause=\"xml write to unspecified 'snap' file skipped\" />\n"
                       "</ntop_dump>\n"
                       "<!--  end of dumpXML -->\n");
            return 0;
        }
#ifdef XMLDUMP_DEBUG
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Opening output file (snap), '%s'\n", myGlobals.xmlFileSnap);
#endif
        fdOut = fopen(myGlobals.xmlFileSnap, "wb");
    }

    if (effectiveDumpToFile == 1) {
        if (fdOut == NULL) {
            traceEvent(CONST_TRACE_ERROR, "XMLDUMP: fopen(xmlout/snap, 'wb'): failed, errno %d\n", errno);
            return 1;
        }
    }

    /* Create a unique temp name and have gdome dump the generated xml to it */

    sprintf(tmpFileName, "%s-%lu", CONST_XML_TMP_NAME, myGlobals.numHandledHTTPrequests);
#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Dumping dom to temp file, '%s'\n", tmpFileName);
#endif

    gdome_di_saveDocToFile(domimpl, doc, tmpFileName, GDOME_SAVE_LIBXML_INDENT, &exc);
    if (exc) {
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP: saveDocToFile(): failed, Exception #%d\n", exc);
        return 1;
#ifdef XMLDUMP_DEBUG
    } else {
        traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Dumping dom, exc=0\n");
#endif
    }       

    /* Open the temp file we created and start echoing it */
    fdTemp = fopen(tmpFileName, "rb");
    if (fdTemp == NULL) {
#ifdef XMLDUMP_DEBUG
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP_DEBUG: fopen(, \"rb\"), errno=%d\n", errno);
#endif
    }

    len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fdTemp);
#if (XMLDUMP_DEBUG >= 2)
    traceEvent(CONST_TRACE_ERROR, "XMLDUMP_DEBUG: INITIAL fread(), len=%d, '%s'n", len, tmpStr);
#endif
    if ( (len > 0) && 
         ( (doctypeHeader = strstr(tmpStr, "?>")) != NULL) ) {
        doctypeHeader += 3; /* skip over ?> and the \n */
        if (effectiveDumpToFile == 1) {
            fwrite(tmpStr, sizeof(char), (doctypeHeader-tmpStr), fdOut);
        } else {
            sendStringLen(tmpStr, (doctypeHeader-tmpStr));
        }

        if (strncmp(doctypeHeader, "<!DOCTYPE", sizeof("<!DOCTYPE")) != 0) {
            if (snprintf(buf, sizeof(buf), "<!DOCTYPE %s SYSTEM \"%s\">\n",
                                           CONST_XML_DOCTYPE_NAME,
                                           dtdURI) < 0)
                BufferTooShort();
            if (effectiveDumpToFile == 1) {
                fwrite(buf, sizeof(char), strlen(buf), fdOut);
            } else {
                sendString(buf);
            }
        }
        if (effectiveDumpToFile == 1) {
            fwrite(doctypeHeader, sizeof(char), len-(doctypeHeader-tmpStr), fdOut);
        } else {
            sendStringLen(doctypeHeader, len-(doctypeHeader-tmpStr));
        }
        len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fdTemp);
#if (XMLDUMP_DEBUG >= 2)
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP_DEBUG: SECOND fread(), len=%d, '%s'n", len, tmpStr);
#endif
    }

    while (len > 0) {
        if (effectiveDumpToFile == 1) {
            fwrite(tmpStr, sizeof(char), len, fdOut);
        } else {
            sendStringLen(tmpStr, len);
        }
        len = fread(tmpStr, sizeof(char), sizeof(tmpStr)-1, fdTemp);
    }

    fclose(fdTemp);

    unlink(tmpFileName);

    if (effectiveDumpToFile == 1) {
        fclose(fdOut);
        if (dumpToFile == 0) {
            sendString("<?xml version=\"1.0\" ?>\n"
                       "<ntop_dump>\n"
                       "<ntop_dump_tofile status=\"completed\" />\n"
                       "</ntop_dump>\n"
                       "<!--  end of dumpXML -->\n");
        }
    }

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Ending dumpXML_writeout\n");
#endif

    return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


RETSIGTYPE xml_sighandler(int signo) {
    signal(SIGSEGV, xml_sighandler);
    segv_count++;
}


int dumpXML(int dumpToFile, char * options) {
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
    int dumpVersion     = TRUE, 
        dumpInvoke = TRUE,
        dumpInterfaces  = FALSE,
        effectiveDumpToFile;

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Starting dumpXML\n");
#endif

    /* **********************************************************************************
     * Initialize options
     * ********************************************************************************** */
    effectiveDumpToFile=dumpToFile;

    /* **********************************************************************************
     * Process options
     * ********************************************************************************** */
    if (options != NULL) {
        char *tmpStr, *strtokState;
        int limit=0;

        tmpStr = strtok_r(options, "&", &strtokState);

        while (tmpStr != NULL) {
            int i=0;

            limit++;
            if (limit > 10) { break; }

#if (XMLDUMP_DEBUG >= 2)
            traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Processing parameter, %2d. '%s'\n", limit, tmpStr);
#endif

            while ((tmpStr[i] != '\0') && (tmpStr[i] != '='))
                i++;

            if (tmpStr[i] == '=') {
                tmpStr[i] = 0;

                if (strncasecmp(tmpStr, CONST_XMLDUMP_VERSION, CONST_XMLDUMP_TEST_LEN) == 0) {
                    if (strncasecmp(&tmpStr[i+1], "y", 1) == 0)
                        dumpVersion=TRUE;
                    else if (strncasecmp(&tmpStr[i+1], "n", 1) == 0)
                        dumpVersion=FALSE;
                } else if (strncasecmp(tmpStr, CONST_XMLDUMP_INVOKE, CONST_XMLDUMP_TEST_LEN) == 0) {
                    if (strncasecmp(&tmpStr[i+1], "y", 1) == 0)
                        dumpInvoke=TRUE;
                    else if (strncasecmp(&tmpStr[i+1], "n", 1) == 0)
                        dumpInvoke=FALSE;
                } else if(strncasecmp(tmpStr, CONST_XMLDUMP_INTERFACES, CONST_XMLDUMP_TEST_LEN) == 0) {
                    if (strncasecmp(&tmpStr[i+1], "y", 1) == 0)
                        dumpInterfaces=TRUE;
                    else if (strncasecmp(&tmpStr[i+1], "n", 1) == 0)
                        dumpInterfaces=FALSE;
                } else if(strncasecmp(tmpStr, CONST_XMLDUMP_TOFILE, CONST_XMLDUMP_TEST_LEN) == 0) {
                    if (strncasecmp(&tmpStr[i+1], "y", 1) == 0)
                        effectiveDumpToFile=TRUE;
                    else if (strncasecmp(&tmpStr[i+1], "n", 1) == 0)
                        effectiveDumpToFile=FALSE;
                }
            }

            tmpStr = strtok_r(NULL, "&", &strtokState);
        }

    }

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Invoked... tofile(%s/%s) version(%s) invoke(%s) interfaces(%s)\n",
               dumpToFile == TRUE ? "Yes" : "No",
               effectiveDumpToFile == TRUE ? "Yes" : "No",
               dumpVersion == TRUE ? "Yes" : "No",
               dumpInvoke == TRUE ? "Yes" : "No",
               dumpInterfaces == TRUE ? "Yes" : "No");
#endif

    /* ********************************************************************************** 
     *   Setup the dtd URI
     * (we don't bother with gdome_di_createDocumentType 'cause it 
     *  flat out doesn't work)
     */
/* TODO Schema? */
    if (snprintf(buf, sizeof(buf), "%s://%s:%d/%s", 
                                   myGlobals.webPort != 0 ? "http" : 
                                                            (myGlobals.sslPort != 0 ? "https" : 
                                                                                      "file"),
                                   myGlobals.hostName,
                                   myGlobals.webPort != 0 ? myGlobals.webPort : 
                                                            (myGlobals.sslPort != 0 ? myGlobals.sslPort : 
                                                                                      0),
                                   CONST_XML_DTD_NAME) < 0)
        BufferTooShort();
    dtdURI = strdup(buf);

    /* ********************************************************************************** */

    xml_new_act.sa_flags=SA_RESTART;
    xml_new_act.sa_handler = xml_sighandler;
    sigemptyset(&xml_new_act.sa_mask);

    rc = sigaction(SIGSEGV, &xml_new_act, &xml_old_act);
#ifdef DEBUG
    snprintf(buf, sizeof(buf), "OTHER(%d)", rc);
    traceEvent(CONST_TRACE_INFO, "DEBUG: set - sigaction(SIGSEGV,,) rc = %s\n",
            (rc == 0      ? "OK"     : 
            (rc == EINVAL ? "EINVAL" : 
            (rc == EFAULT ? "EFAULT" : 
            (rc == EINTR  ? "EINTR"  : buf) ) ) ) );
#endif

    /* Get a DOMImplementation reference - does the startup for libxml, gdome et al
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
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP: createDocument: failed, Exception #%d\n", exc);
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
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP: createDocumentType: failed, Exception #%d\n", exc);
        gdome_di_unref (domimpl, &exc);
        return 1;
    }
    /* From here on, we have a structure, so we have to continue on to free everything */
    root = gdome_doc_documentElement(doc, &exc);
    if (exc) {
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP: documentElement(root): failed, Exception #%d\n", exc);
        rc=exc;
    }

/* IGNORE FOR NOW
    result = gdome_doc_appendChild(doc, (GdomeNode *)dt, &exc);
    if (exc) {
        traceEvent(CONST_TRACE_ERROR, "XMLDUMP: appendChild[dt]: failed, Exception #%d\n", exc);
        rc=exe;
    }
*/

    /* ********************************************************************************** 
     *   We always dump the header and command line -- the rest is controlled by flags...
     */

    if (rc == 0) {
        el = dumpXML_createHeader(dumpToFile, effectiveDumpToFile);
        if (el == NULL) { 
            traceEvent(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_createHeader() is NULL\n");
            rc = 1;
        } 
    }

    if ( (rc == 0) && (dumpVersion == TRUE) ) {
        el = dumpXML_versioncHeader();
        if (el == NULL) { 
            traceEvent(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_versioncHeader() is NULL\n");
            rc = 1;
        } 
    }

    if ( (rc == 0) && (dumpInvoke == TRUE) ) {
        el = dumpXML_invoke();
        if (el == NULL) { 
            traceEvent(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_invoke() is NULL\n");
            rc = 1;
        }
    }

    if ( (rc == 0) && (dumpInterfaces == TRUE) ) {
        el = dumpXML_interfaces();
        if (el == NULL) {
            traceEvent(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_interfaces() is NULL\n");
            rc = 1;
        }
    } 

    /* ********************************************************************************** */

    /* walk the created document and write it out */
    if (rc == 0) {
        rc = dumpXML_writeout(dumpToFile, effectiveDumpToFile);
        if (rc != 0)
            traceEvent(CONST_TRACE_INFO, "XMLDUMP: return from dumpXML_writeout() is %d\n", rc);
    }

    sendString("<!-- end of dumpXML -->\n");

    /* ********************************************************************************** */

    /* free the document structure and the DOMImplementation */
        /* TODO Do we need to free dt ? */
    gdome_di_freeDoc (domimpl, doc, &exc);
    gdome_di_unref (domimpl, &exc);

    /* ********************************************************************************** */

#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Finished with dumpXML");
#endif

    rc = sigaction(SIGSEGV, &xml_old_act, NULL);
#ifdef DEBUG
    snprintf(buf, sizeof(buf), "OTHER(%d)", rc);
    traceEvent(CONST_TRACE_INFO, "DEBUG: Restore - sigaction(SIGSEGV,,) rc = %s, SIGSEGV count %d\n",
            (rc == 0      ? "OK"     : 
            (rc == EINVAL ? "EINVAL" : 
            (rc == EFAULT ? "EFAULT" : 
            (rc == EINTR  ? "EINTR"  : buf) ) ) ),
            segv_count);
#endif

    return 0;

}

#else

int dumpXML(int dumpToFile, char * options) {
#ifdef XMLDUMP_DEBUG
    traceEvent(CONST_TRACE_INFO, "XMLDUMP_DEBUG: Disabled version of dumpXML (nop)");
#endif
    return 0;
}

#endif /* MAKE_WITH_XMLDUMP */

/* ******************************* */
