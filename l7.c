/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 *           Copyright (C) 2006-09 Luca Deri <deri@ntop.org>
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

#if defined(HAVE_LIBPCRE) && defined(HAVE_PCRE_H)

/* *********************************** */

struct plugin_info {
  char *protocol_name;
};

/* *********************************************** */

struct proto_info {
  char *proto_name;
  pcre *proto_regex;
  struct proto_info *next;
};

static struct proto_info *proto_root = NULL;
static u_int num_patterns;

#define CONST_PATTERN_EXTENSION   ".pat"

#define MAX_BYTES_SENT            1024
#define MAX_BYTES_RCVD            1024

/* ******************************************* */

static struct proto_info* loadPattern(char *base_dir, char *pattern_filename) {
  FILE *fd;
  struct proto_info *proto;
  char path[512];

  proto = (struct proto_info*)malloc(sizeof(struct proto_info));
  if(proto == NULL) {
    traceEvent(CONST_TRACE_WARNING, "Not enough memory while loading pattern");
    return(NULL);
  } else
    memset(proto, 0, sizeof(struct proto_info));

  snprintf(path, sizeof(path), "%s/%s", base_dir, pattern_filename);
  fd = fopen(path, "r");

  if(fd) {
    char buffer[512];

    while((!feof(fd)) && (fgets(buffer, sizeof(buffer), fd) != NULL)) {
      if((buffer[0] != '#')
	 && (buffer[0] != ' ') && (buffer[0] != '\n')
	 && (buffer[0] != '\r') && (buffer[0] != '\t')) {
	buffer[strlen(buffer)-1] = '\0';

	if(proto->proto_name == NULL)
	  proto->proto_name = strdup(buffer);
	else if(proto->proto_regex == NULL) {
	  const char *error;
	  int erroffset;

	  proto->proto_regex = pcre_compile(buffer,               /* the pattern */
					    0,                    /* default options */
					    &error,               /* for error message */
					    &erroffset,           /* for error offset */
					    NULL);                /* use default character tables */
	  
	  if(proto->proto_regex == NULL) {
	    if(proto->proto_name != NULL) free(proto->proto_name);
	    free(proto);
            return(NULL);
	    traceEvent(CONST_TRACE_WARNING, "Invalid pattern (%s). Skipping...", error);
	  }

	  break;
	}
      }
    }

    fclose(fd);
  } else
    traceEvent(CONST_TRACE_WARNING, "Unable to read pattern file %s", path);
  
  if(proto->proto_name && proto->proto_regex)
    return(proto);
  else {
    free(proto);
    return(NULL);
  }
}

/* ******************************************* */

void initl7() {
  DIR* directoryPointer = NULL;
  char* dirPath = "l7-patterns/";
  struct dirent* dp;
  struct proto_info *the_proto;

  proto_root = NULL;
  num_patterns = 0;

  if((directoryPointer = opendir(dirPath)) == NULL) {
    traceEvent(CONST_TRACE_INFO, "Unable to read directory '%s'", dirPath);
    return;
  }

  while((dp = readdir(directoryPointer)) != NULL) {
    if(dp->d_name[0] == '.')
      continue;
    else if(strlen(dp->d_name) < strlen(CONST_PATTERN_EXTENSION))
      continue;

    traceEvent(CONST_TRACE_INFO, "Loading pattern %s", dp->d_name);

    the_proto = loadPattern(dirPath, dp->d_name);

    if(the_proto) {
      the_proto->next = proto_root;
      proto_root = the_proto;
      num_patterns++;
    }
  }

  closedir(directoryPointer);

  traceEvent(CONST_TRACE_INFO, "Loaded %d patterns", num_patterns);
}

/* *********************************************** */

static char* protocolMatch(u_char *payload, int payloadLen) {
  struct proto_info *scanner = proto_root;
  
  // traceEvent(CONST_TRACE_INFO, "protocolMatch(%d)", payloadLen);
  
  while(scanner) {
    // traceEvent(CONST_TRACE_INFO, "protocolMatch(%s, %d)", scanner->proto_name, payloadLen);

    int rc = pcre_exec(
		   scanner->proto_regex, /* the compiled pattern */
		   NULL,                 /* no extra data - we didn't study the pattern */
		   (char*)payload,       /* the subject string */
		   payloadLen,           /* the length of the subject */
		   0,                    /* start at offset 0 in the subject */
		   PCRE_PARTIAL,         /* default options */
		   NULL,                 /* output vector for substring information */
		   0);                   /* number of elements in the output vector */
    
    if(rc >= 0) {
      // traceEvent(CONST_TRACE_INFO, "MATCH: protocolMatch(%s, %d)", scanner->proto_name, payloadLen);

      return(scanner->proto_name);
    } else {
      // traceEvent(CONST_TRACE_ERROR, "pcre_exec returned %d", rc);
    }
    
    scanner = scanner->next;
  }

  return(NULL);
}

/* ******************************************* */

void l7SessionProtoDetection(IPSession *theSession, 
			     u_int packetDataLength, 
			     u_char* packetData) {

  if((theSession== NULL) 
     || (theSession->guessed_protocol != NULL)
     || (packetDataLength == 0)) 
    return;

  if((theSession->bytesProtoSent.value > MAX_BYTES_SENT)
     || (theSession->bytesProtoRcvd.value > MAX_BYTES_RCVD)) 
    return;

  if(theSession->guessed_protocol == NULL) {
    char *proto = protocolMatch(packetData, packetDataLength);

    if(proto) 
      theSession->guessed_protocol = strdup(proto);
  }
}

#endif /* HAVE_LIBPCRE */
