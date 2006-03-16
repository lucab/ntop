/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 * Copyright (C) 2006 Luca Deri <deri@ntop.org>
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

#ifdef HAVE_MYSQL_H

static u_char mysql_initialized;
static MYSQL mysql;

/* ***************************************************** */

static int exec_sql_query(char *sql) {
  //traceEvent(CONST_TRACE_ERROR, "====> %s", sql);

  if(mysql_query(&mysql, sql)) {
    traceEvent(CONST_TRACE_ERROR, "MySQL error: %s", mysql_error(&mysql));
    return(-1);
  } else
    return(0);
}

/* ***************************************************** */

static char *get_last_db_error() {
  /*  if(!mysql_initialized)
    return("");
    else*/
    return((char*)mysql_error(&mysql));
}

/* ***************************************************** */

static int init_database(char *db_host, char* user, char *pw, char *db_name) {
  char sql[2048];

  mysql_initialized = 0;

  if(mysql_init(&mysql) == NULL) {
    traceEvent(CONST_TRACE_ERROR, "Failed to initate MySQL connection");
    return(-1);
  }

  if(!mysql_real_connect(&mysql, db_host, user, pw, NULL, 0, NULL, 0)){
    traceEvent(CONST_TRACE_ERROR, "Failed to connect to MySQL: %s\n",
	       mysql_error(&mysql));
    return(-2);
  } else
    traceEvent(CONST_TRACE_INFO, "Succesfully connected to MySQL");
  
  /* *************************************** */
  
  snprintf(sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS %s", db_name);
  if(exec_sql_query(sql) != 0) {
    traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-3);
  }

  if(mysql_select_db(&mysql, db_name)) {
    traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-4);
  }

  /* *************************************** */
  
  /* Sessions */
  snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS `sessions` ("
	   "`idx` int(11) NOT NULL auto_increment,"
	   "`proto` smallint(3) NOT NULL default '0',"
	   "`src` varchar(32) NOT NULL default '',"
	   "`dst` varchar(32) NOT NULL default '',"
	   "`sport` smallint(6) NOT NULL default '0',"
	   "`dport` smallint(6) NOT NULL default '0',"
	   "`pktSent` int(11) NOT NULL default '0',"
	   "`pktRcvd` int(11) NOT NULL default '0',"
	   "`bytesSent` int(11) NOT NULL default '0',"
	   "`bytesRcvd` int(11) NOT NULL default '0',"
	   "`firstSeen` int(11) NOT NULL default '0',"
	   "`lastSeen` int(11) NOT NULL default '0',"
	   "`nwLatency` float(6,2) NOT NULL default '0',"
	   "`isP2P` smallint(1) NOT NULL default '0',"
	   "`isVoIP` smallint(1) NOT NULL default '0',"
	   "`isPassiveFtp` smallint(1) NOT NULL default '0',"
	   "`info`   varchar(64) NOT NULL default '',"
	   "`guessedProto`   varchar(16) NOT NULL default '',"
	   "UNIQUE KEY `idx` (`idx`)"
	   ") ENGINE=MyISAM DEFAULT CHARSET=latin1");

  if(exec_sql_query(sql) != 0) {
    traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-5);
  }

  /* *************************************** */
  
  /* NetFlow */
  snprintf(sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS `flows` ("
	   "`idx` int(11) NOT NULL auto_increment,"
	   "`probeId` smallint(6) NOT NULL default '0',"
	   "`srcAddr` int(11) NOT NULL default '0',"
	   "`dstAddr` int(11) NOT NULL default '0',"
	   "`nextHop` int(11) NOT NULL default '0',"
	   "`input` smallint(6) NOT NULL default '0',"
	   "`output` smallint(6) NOT NULL default '0',"
	   "`sentPkts` int(11) NOT NULL default '0',"
	   "`rcvdPkts` int(11) NOT NULL default '0',"
	   "`sentOctets` int(11) NOT NULL default '0',"
	   "`rcvdOctets` int(11) NOT NULL default '0',"
	   "`first` int(11) NOT NULL default '0',"
	   "`last` int(11) NOT NULL default '0',"
	   "`srcPort` smallint(6) NOT NULL default '0',"
	   "`dstPort` smallint(6) NOT NULL default '0',"
	   "`tcpFlags` smallint(3) NOT NULL default '0',"
	   "`proto` smallint(3) NOT NULL default '0',"
	   "`tos` smallint(3) NOT NULL default '0',"
	   "`dstAS` smallint(6) NOT NULL default '0',"
	   "`srcAS` smallint(6) NOT NULL default '0',"
	   "`srcMask` smallint(3) NOT NULL default '0',"
	   "`dstMask` smallint(3) NOT NULL default '0',"
	   "`vlanId` smallint(6) NOT NULL default '0',"
	   "`processed` tinyint(1) NOT NULL default '0',"
	   "UNIQUE KEY `idx` (`idx`)"
	   ") ENGINE=MyISAM DEFAULT CHARSET=latin1");

  if(exec_sql_query(sql) != 0) {
    traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());
    return(-5);
  }

  mysql_initialized = 1;
  return(0);
}

/* ***************************************************** */

int dump_session_to_db(IPSession *sess) {
  if((!mysql_initialized) || (sess == NULL)) {
    return(-2);
  } else {
    char sql[1024], tmp[32];

    if((sess->lastFlags == 0) || (sess->nwLatency.tv_sec > 100))
      tmp[0] = '\0';
    else {
      int len;

      formatLatency(sess->nwLatency, sess->sessionState, tmp, sizeof(tmp));
      
      len = strlen(tmp);

      if(len > 8) tmp[len-8] = '\0';
    }

    snprintf(sql, sizeof(sql),
	     "INSERT INTO sessions (proto, src, dst, sport, dport,"
	     "pktSent, pktRcvd, bytesSent, bytesRcvd, firstSeen, lastSeen, "
	     "nwLatency, isP2P, isVoIP, isPassiveFtp, info, guessedProto) VALUES "
	     "('%d', '%s', '%s',  '%d', '%d', "
	     " '%lu', '%lu', '%lu', '%lu', '%lu', '%lu', "
	     " '%s',  '%d',  '%d',  '%d',  '%s',  '%s')",
	     (sess->lastFlags == 0) ? 17 /* udp */ : 6 /* tcp */, 
	     sess->initiator->hostNumIpAddress, 
	     sess->remotePeer->hostNumIpAddress, sess->sport, sess->dport, 
	     sess->pktSent, sess->pktRcvd, (unsigned long)sess->bytesSent.value, 
	     (unsigned long)sess->bytesRcvd.value, (unsigned long)sess->firstSeen, (unsigned long)sess->lastSeen, 
	     tmp, sess->isP2P, sess->voipSession, sess->passiveFtpSession, 
	     (sess->session_info == NULL) ? "" : sess->session_info,
	     (sess->guessed_protocol == NULL) ? "" : sess->guessed_protocol);

    //traceEvent(CONST_TRACE_ERROR, "-> %s", sql);

    if(mysql_query(&mysql, sql)) {
      traceEvent(CONST_TRACE_WARNING, "%s", mysql_error(&mysql));
      return(-1);
    } else {
      /*
	insert_id = mysql_insert_id(&mysql);
	printf("You inserted \"%d\".\n", insert_id);
      */
      return(0);
    }
  }
}

/* ***************************************************** */

int insert_flow_record(u_int16_t probeId,
		       u_int32_t srcAddr, u_int32_t dstAddr,
		       u_int16_t input, u_int16_t output,
		       u_int32_t sentPkts, u_int32_t sentOctets,
		       u_int32_t rcvdPkts, u_int32_t rcvdOctets,
		       u_int32_t first, u_int32_t last,
		       u_int16_t srcPort, u_int16_t dstPort, u_int8_t tcpFlags,
		       u_int8_t proto, u_int8_t tos, u_int16_t vlanId) {
  if(!mysql_initialized) {
    return(-2);
  } else {
    char sql[1024];

    snprintf(sql, sizeof(sql),
	     "INSERT INTO flows (probeId, srcAddr, dstAddr, input, output, "
	     "sentPkts, rcvdPkts, sentOctets, rcvdOctets, first, last,"
	     "srcPort, dstPort, tcpFlags, proto, tos, vlanId) VALUES "
	     "('%d', '%d', '%d',  '%d', '%d',  '%d',  '%d',  '%d', "
	     " '%d',  '%d',  '%d',  '%d',  '%d',  '%d', '%d', '%d', '%d')",
	     probeId, srcAddr, dstAddr, input, output, sentPkts,
	     rcvdPkts, sentOctets, rcvdOctets, first, last,
	     srcPort, dstPort, tcpFlags, proto, tos, vlanId);

    traceEvent(CONST_TRACE_INFO, "%s", sql);

    if(mysql_query(&mysql, sql)) {
      traceEvent(CONST_TRACE_WARNING, "%s", mysql_error(&mysql));
      return(-1);
    } else {
      /*
	insert_id=mysql_insert_id(&mysql);
	printf("You inserted \"%d\".\n", insert_id);
      */
      return(0);
    }
  }
}

/* ***************************************************** */

static void term_database() {
  if(mysql_initialized) {
    mysql_close(&mysql);
    mysql_initialized = 0;
  }
}

/* ***************************************************** */

void initDB() {
  init_database("localhost", "root", "", "ntop");
}

/* ***************************************************** */

void termDB() {
  term_database();
}

/* ***************************************************** */

#else

void initDB() { traceEvent(CONST_TRACE_INFO, "Database support not compiled into ntop"); }
void termDB() { ; }
int dump_session_to_db(IPSession *sess) { return(0); }
int insert_flow_record(u_int16_t probeId,
		       u_int32_t srcAddr, u_int32_t dstAddr,
		       u_int16_t input, u_int16_t output,
		       u_int32_t sentPkts, u_int32_t sentOctets,
		       u_int32_t rcvdPkts, u_int32_t rcvdOctets,
		       u_int32_t first, u_int32_t last,
		       u_int16_t srcPort, u_int16_t dstPort, u_int8_t tcpFlags,
		       u_int8_t proto, u_int8_t tos, u_int16_t vlanId) { return(-1); }
#endif
