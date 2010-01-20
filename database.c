/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *                          http://www.ntop.org
 *
 *            Copyright (C) 2006-10 Luca Deri <deri@ntop.org>
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

u_int32_t num_db_insert = 0, num_db_insert_failed = 0;

#ifdef HAVE_MYSQL_H

static PthreadMutex mysql_mutex;
static u_char mysql_initialized = 0, mysql_mutex_initialized = 0;
static MYSQL mysql;
static char mysql_db_host[32], mysql_db_user[32], mysql_db_pw[32], mysql_db_name[32];

static int init_database(char *db_host, char* user, char *pw, char *db_name);


/* ***************************************************** */

int is_db_enabled() { return(mysql_initialized); }

/* ***************************************************** */

#if 0
static void reconnect_to_db() {
 init_database(mysql_db_host, mysql_db_user, mysql_db_pw, mysql_db_name);
}
#endif

/* ***************************************************** */

static int exec_sql_query(char *sql) {
  /* traceEvent(CONST_TRACE_ERROR, "====> %s", sql); */

  if(!mysql_initialized) return(-2);

  accessMutex(&mysql_mutex, "exec_sql_query");

  if(mysql_query(&mysql, sql)) {
    int err_id = mysql_errno(&mysql);

    traceEvent(CONST_TRACE_ERROR, "MySQL error: %s [%d][%s]",
	       mysql_error(&mysql), err_id, sql);

    if(err_id == CR_SERVER_GONE_ERROR) {
      // mysql_close(&mysql);
      mysql_initialized = 0;
      return(-1);
    }

    releaseMutex(&mysql_mutex);
    return(-1);
  } else {
    releaseMutex(&mysql_mutex);
    return(0);
  }
}

/* ***************************************************** */

static char *get_last_db_error() {
  if(!mysql_initialized)
    return("");
  else
    return((char*)mysql_error(&mysql));
}

/* ***************************************************** */

static void* scanDbLoop(void* notUsed _UNUSED_) {
  char buf[32];

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: DB: Database purge loop",
             pthread_self());

  for(;;) {    
    if(fetchPrefsValue(NTOP_PREF_SQL_REC_LIFETIME, buf, sizeof(buf)) == -1) {
      safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%u", 
		    myGlobals.runningPref.sqlRecDaysLifetime);
      storePrefsValue(NTOP_PREF_SQL_REC_LIFETIME, buf);
    }

    ntopSleepWhileSameState(86400); /* 1 day */

    if((myGlobals.ntopRunState > FLAG_NTOPSTATE_RUN)
       ||  (!mysql_initialized))
      break;

    /* Read purge preference just in time it changed */
    if(fetchPrefsValue(NTOP_PREF_SQL_REC_LIFETIME, buf, sizeof(buf)) != -1)
      myGlobals.runningPref.sqlRecDaysLifetime = atoi(buf);    

    if(myGlobals.runningPref.sqlRecDaysLifetime > 0) {
      char sql[256];
      time_t now = time(NULL);

      now -=  myGlobals.runningPref.sqlRecDaysLifetime*86400;
      
      safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql),
		    "DELETE FROM sessions WHERE lastSeen < %u", now);

      if(exec_sql_query(sql) != 0)
	traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());

      /* ************************************ */

      safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql),
		    "DELETE FROM flows WHERE last < %u", now);

      if(exec_sql_query(sql) != 0)
	traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error());      
    }
  }

  traceEvent(CONST_TRACE_INFO, "THREADMGMT[t%lu]: DB: Database purge loop terminated",
             pthread_self());

  return(NULL);
}

/* ***************************************************** */

static int init_database(char *db_host, char* user, char *pw, char *db_name) {
  char sql[2048];

  mysql_initialized = 0;
  myGlobals.purgeDbThreadId = (pthread_t)-1;

  if(!mysql_mutex_initialized) createMutex(&mysql_mutex);
  mysql_mutex_initialized = 1;

  if(db_host == NULL)  db_host = "localhost";
  if(pw == NULL)       pw = "";
  if(user == NULL)     user = "";

  if(mysql_init(&mysql) == NULL) {
    traceEvent(CONST_TRACE_ERROR, "Failed to initate MySQL connection");
    return(-1);
  }

  if(!mysql_real_connect(&mysql, db_host, user, pw, NULL, 0, NULL, 0)){
    traceEvent(CONST_TRACE_ERROR, "Failed to connect to MySQL: %s [%s:%s:%s:%s]\n",
	       mysql_error(&mysql), db_host, user, pw, db_name);
    return(-2);
  } else {
    traceEvent(CONST_TRACE_INFO, "Successfully connected to MySQL [%s:%s:%s:%s]",
	       db_host, user, pw, db_name);
    safe_snprintf(__FILE__, __LINE__, mysql_db_host, sizeof(mysql_db_host), db_host);
    safe_snprintf(__FILE__, __LINE__, mysql_db_user, sizeof(mysql_db_user), user);
    safe_snprintf(__FILE__, __LINE__, mysql_db_pw, sizeof(mysql_db_pw), pw);
    safe_snprintf(__FILE__, __LINE__, mysql_db_name, sizeof(mysql_db_name), db_name);
  }

#ifdef MYSQL_OPT_RECONNECT
 {
   my_bool autoreconnect = 1;
   
   mysql_options(&mysql, MYSQL_OPT_RECONNECT, &autoreconnect);
 }
#endif

  mysql_initialized = 1;

  /* *************************************** */

  safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS %s", db_name);
  if(exec_sql_query(sql) != 0) {
    /* traceEvent(CONST_TRACE_ERROR, "MySQL error: %s", get_last_db_error()); */
    return(-3);
  }

  if(mysql_select_db(&mysql, db_name)) {
    /* traceEvent(CONST_TRACE_ERROR, "MySQL error: %s", get_last_db_error()); */
    return(-4);
  }

  /* ************************************************ */

  /* NetFlow */
  safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS `flows` ("
		"`idx` int(11) NOT NULL auto_increment,"
		"`probeId` smallint(6) NOT NULL default '0',"
		"`src` varchar(32) NOT NULL default '',"
		"`dst` varchar(32) NOT NULL default '',"
		"`nextHop` int(11) NOT NULL default '0',"
		"`input` mediumint(6) NOT NULL default '0',"
		"`output` mediumint(6) NOT NULL default '0',"
		"`pktSent` int(11) NOT NULL default '0',"
		"`pktRcvd` int(11) NOT NULL default '0',"
		"`bytesSent` int(11) NOT NULL default '0',"
		"`bytesRcvd` int(11) NOT NULL default '0',"
		"`first` int(11) NOT NULL default '0',"
		"`last` int(11) NOT NULL default '0',"
		"`sport` mediumint(6) NOT NULL default '0',"
		"`dport` mediumint(6) NOT NULL default '0',"
		"`tcpFlags` smallint(3) NOT NULL default '0',"
		"`proto` smallint(3) NOT NULL default '0',"
		"`tos` tinyint(4) NOT NULL default '0',"
		"`dstAS` mediumint(6) NOT NULL default '0',"
		"`srcAS` mediumint(6) NOT NULL default '0',"
		"`srcMask` tinyint(4) NOT NULL default '0',"
		"`dstMask` tinyint(4) NOT NULL default '0',"
		"`vlanId` smallint(6) NOT NULL default '0',"
		"`processed` tinyint(1) NOT NULL default '0',"
		"UNIQUE KEY `idx` (`idx`),"
		" KEY `src` (`src`),"
		" KEY `dst` (`dst`),"
		" KEY `first` (`first`),"
		" KEY `last` (`last`),"
		" KEY `sport` (`sport`),"
		" KEY `dport` (`dport`),"
		" KEY `probeId` (`probeId`)"
		") ENGINE=MyISAM DEFAULT CHARSET=latin1");

  if(exec_sql_query(sql) != 0) {
    /* traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error()); */
    return(-5);
  }

  /* ************************************************ */

  /* NetFlow */
  safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql), "CREATE TABLE IF NOT EXISTS `sessions` ("
		"`idx` int(11) NOT NULL auto_increment,"
		"`proto` smallint(3) NOT NULL default '0',"
		"`src` varchar(32) NOT NULL default '',"
		"`dst` varchar(32) NOT NULL default '',"
		"`sport` mediumint(6) NOT NULL default '0',"
		"`dport` mediumint(6) NOT NULL default '0',"
		"`pktSent` int(11) NOT NULL default '0',"
		"`pktRcvd` int(11) NOT NULL default '0',"
		"`bytesSent` int(11) NOT NULL default '0',"
		"`bytesRcvd` int(11) NOT NULL default '0',"
		"`firstSeen` int(11) NOT NULL default '0',"
		"`lastSeen` int(11) NOT NULL default '0',"
		"`clientNwDelay` float(6,2) NOT NULL default '0.00',"
		"`serverNwDelay` float(6,2) NOT NULL default '0.00',"
		"`isP2P` smallint(1) NOT NULL default '0',"
		"`isVoIP` smallint(1) NOT NULL default '0',"
		"`isPassiveFtp` smallint(1) NOT NULL default '0',"
		"`info` varchar(64) NOT NULL default '',"
		"`guessedProto` varchar(16) NOT NULL default '',"
		" UNIQUE KEY `idx` (`idx`),"
		" KEY `src` (`src`),"
		" KEY `dst` (`dst`),"
		" KEY `firstSeen` (`firstSeen`),"
		" KEY `lastSeen` (`lastSeen`),"
		" KEY `sport` (`sport`),"
		" KEY `dport` (`dport`)"	     
		") ENGINE=MyISAM DEFAULT CHARSET=latin1");

  if(exec_sql_query(sql) != 0) {
    /* traceEvent(CONST_TRACE_ERROR, "MySQL error: %s\n", get_last_db_error()); */
    return(-5);
  }

  /* ************************************************ */

  createThread(&myGlobals.purgeDbThreadId, scanDbLoop, NULL);

  /* ************************************************ */

  return(0);
}

/* ***************************************************** */

int dump_session_to_db(IPSession *sess) {
  
  /*
  traceEvent(CONST_TRACE_INFO, "dump_session_to_db(saveRecordsIntoDb=%d)(saveSessionsIntoDb=%d)",
    myGlobals.runningPref.saveRecordsIntoDb, myGlobals.runningPref.saveSessionsIntoDb);
  */

  if(myGlobals.runningPref.saveSessionsIntoDb == 0) return(0);

  if((!mysql_initialized) || (sess == NULL)) {
    return(-2);
  } else {
    char sql[1024], clientNwDelay[32] = { 0 }, serverNwDelay[32] = { 0 };

    if((sess->lastFlags == 0) 
       || (sess->clientNwDelay.tv_sec > 100) /* Too large */
       || (sess->serverNwDelay.tv_sec > 100) /* Too large */
       )
      clientNwDelay[0] = '\0', serverNwDelay[0] = '\0';
    else {
      int len;

      formatLatency(sess->clientNwDelay, sess->sessionState, clientNwDelay, sizeof(clientNwDelay));
      len = strlen(clientNwDelay); if(len > 8) clientNwDelay[len-8] = '\0';
      formatLatency(sess->serverNwDelay, sess->sessionState, serverNwDelay, sizeof(serverNwDelay));
      len = strlen(serverNwDelay); if(len > 8) serverNwDelay[len-8] = '\0';
    }

    safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql),
		  "INSERT INTO sessions (proto, src, dst, sport, dport,"
		  "pktSent, pktRcvd, bytesSent, bytesRcvd, firstSeen, lastSeen, "
		  "clientNwDelay, serverNwDelay, isP2P, isVoIP, "
		  "isPassiveFtp, info, guessedProto) VALUES "
		  "('%d', '%s', '%s',  '%d', '%d', "
		  " '%lu', '%lu', '%lu', '%lu', '%lu', '%lu', "
		  " '%s', '%s', '%d',  '%d',  '%d',  '%s',  '%s')",
		  (sess->lastFlags == 0) ? 17 /* udp */ : 6 /* tcp */,
		  sess->initiator->hostNumIpAddress,
		  sess->remotePeer->hostNumIpAddress, sess->sport, sess->dport,
		  sess->pktSent, sess->pktRcvd, (unsigned long)sess->bytesSent.value,
		  (unsigned long)sess->bytesRcvd.value, (unsigned long)sess->firstSeen,
		  (unsigned long)sess->lastSeen,
		  clientNwDelay, serverNwDelay, sess->isP2P, sess->voipSession, sess->passiveFtpSession,
		  (sess->session_info == NULL) ? "" : sess->session_info,
		  (sess->guessed_protocol == NULL) ? "" : sess->guessed_protocol);

    // traceEvent(CONST_TRACE_ERROR, "-> %s", sql);

    if(exec_sql_query(sql)) {
      num_db_insert_failed++;
      traceEvent(CONST_TRACE_WARNING, "%s", mysql_error(&mysql));
      return(-1);
    } else {
      /*
	insert_id = mysql_insert_id(&mysql);
	printf("You inserted \"%d\".\n", insert_id);
      */
      num_db_insert++;
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

  if(myGlobals.runningPref.saveRecordsIntoDb == 0) return(0);

  if(!mysql_initialized) {
    return(-2);
  } else {
    char sql[1024], buf1[32], buf2[32];

    struct in_addr a, b;

    a.s_addr = srcAddr, b.s_addr = dstAddr;

    safe_snprintf(__FILE__, __LINE__, sql, sizeof(sql),
		  "INSERT INTO flows (probeId, src, dst, input, output, "
		  "pktSent, pktRcvd, bytesSent, bytesRcvd, first, last, "
		  "sport, dport, tcpFlags, proto, tos, vlanId) VALUES "
		  "('%d', '%s', '%s',  '%u', '%u',  '%lu',  '%lu',  '%lu', "
		  "'%lu',  '%lu',  '%lu',  '%u',  '%u',  '%u', '%d', '%d', '%d')",
		  probeId, _intoa(a, buf1, sizeof(buf1)),
		  _intoa(b, buf2, sizeof(buf2)),
		  input, output, sentPkts, rcvdPkts,
		  sentOctets, rcvdOctets,
		  first, last, srcPort, dstPort,
		  tcpFlags, proto, tos, vlanId > 4096 ? 0 : vlanId );

    // traceEvent(CONST_TRACE_INFO, "%s", sql);

    if(exec_sql_query(sql)) {
      traceEvent(CONST_TRACE_WARNING, "%s", mysql_error(&mysql));
      num_db_insert_failed++;
      return(-1);
    } else {
      /*
	insert_id=mysql_insert_id(&mysql);
	printf("You inserted \"%d\".\n", insert_id);
      */
      num_db_insert++;
      return(0);
    }
  }
}

/* ***************************************************** */

static void term_database(void) {
  if(mysql_initialized) {
    mysql_close(&mysql);
    mysql_initialized = 0;
  }
}

/* ***************************************************** */

void initDB() {
  char *host = NULL, *user = NULL, *pw = NULL,
    tmpBuf[256] = { 0 }, *strtokState;

  if(myGlobals.runningPref.sqlDbConfig != NULL)
    safe_snprintf(__FILE__, __LINE__, tmpBuf, sizeof(tmpBuf),
		  "%s:", myGlobals.runningPref.sqlDbConfig);

  host = strtok_r(tmpBuf, ":", &strtokState);
  if(host) user = strtok_r(NULL, ":", &strtokState);
  if(user) pw = strtok_r(NULL, ":", &strtokState);

  if((pw && (strlen(pw) == 1 /* it's the space we added */))
     || (!pw))
    pw = "";

  if(host && user && pw)
    init_database(host, user, pw, "ntop");
  else
    traceEvent(CONST_TRACE_ERROR, "Unable to initialize DB: "
	       "please configure the DB prefs [%s][%s][%s]",
	       host, user, pw);
}

/* ***************************************************** */

void termDB() {
  term_database();
}

/* ***************************************************** */

#else

int is_db_enabled() { return(0); }
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
