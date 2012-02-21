/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 *
 *                          http://www.ntop.org
 *
 *           Copyright (C) 1998-2012 Luca Deri <deri@ntop.org>
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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */


#include "ntop.h"

#ifdef HAVE_OPENSSL
#include <openssl/rand.h>

int verify_callback(int ok, X509_STORE_CTX *ctx);

void ntop_ssl_error_report(char * whyMe) {
  unsigned long l;
  char buf[200];
  const char *file,*data;
  int line,flags;
  unsigned long es;

  if(myGlobals.newSock != 0) {
    if(SSL_get_error(getSSLsocket(myGlobals.newSock), -1) == SSL_ERROR_SSL) 
      return; /* Internale OpenSSL failure: can't do much */
  }

  es = CRYPTO_thread_id();
  while ((l=ERR_get_error_line_data(&file,&line,&data,&flags)) != 0) {
    ERR_error_string_n(l, buf, sizeof buf);
    traceEvent(CONST_TRACE_INFO, "SSL(%s)ERROR [Thread %lu]: %s at %s(%d) %s",
	       whyMe,
	       es,
	       buf,
	       file,
	       line,
	       (flags&ERR_TXT_STRING)?data:"");
  }
}

int init_ssl(void) {
  int idx;
  FILE* fd=NULL;
  char     buf [384];
  SSL_METHOD *meth;
  int s_server_session_id_context = 1; /* anything will do */
  DIR* directoryPointer=NULL;
  struct dirent *dp;
  struct stat fStat;

  myGlobals.sslInitialized = 0;

  if(myGlobals.runningPref.sslPort == 0) {
    traceEvent(CONST_TRACE_INFO, "SSL is present but https is disabled: use -W <https port> for enabling it");
    return(0); /* The user decided NOT to use SSL */
  }

  memset(myGlobals.ssl, 0, sizeof(myGlobals.ssl));

  traceEvent(CONST_TRACE_INFO, "SSL: Initializing...");

  /*
   * If necessary, initialize the prng for ssl...
   */
  if (RAND_status() == 0) {
    struct timeval TOD;
    /*
     * If we get here, we need to add some entropy, because it's not there by default
     * and because we don't have egd running.
     *
     * Remember, this is ntop during startup, so we can't just use ntop counters...
     *
     * We need some stuff that's random from ntop user/instance to ntop user/instance
     * and some stuff the user just can't affect.
     *
     * We have to be careful, as some things that might seem random, such as pid# 
     * aren't if ntop is started during boot. OTOP, if the user won't run egd, then
     * well, there's only so much we're going to do...
     */
    traceEvent(CONST_TRACE_INFO, "SSL_PRNG: Initializing.");
    traceEvent(CONST_TRACE_NOISY, "SSL_PRNG: see http://www.openssl.org/support/faq.cgi#USER1.");

    RAND_add(version, strlen(version), (double)4.0);
    RAND_add(buildDate, strlen(buildDate), (double)4.0);
    RAND_add(configure_parameters, strlen(configure_parameters), (double)4.0);

    gettimeofday(&TOD, NULL);
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%d%u%u%x%x%x", 
		  getpid(),
		  TOD.tv_sec,
		  TOD.tv_usec,
		  myGlobals.startedAs,
		  myGlobals.udpSvc,
		  myGlobals.tcpSvc );
    RAND_add(buf, strlen(buf), (double)24.0);

    directoryPointer = opendir(myGlobals.dbPath);
    if (directoryPointer == NULL) {
      traceEvent(CONST_TRACE_WARNING, "SSL_PRNG: Unable to find directory '%s' for additional randomness", myGlobals.dbPath);
    } else {
      while((dp = readdir(directoryPointer)) != NULL) {
	if (dp->d_name[0] != '.') {
	  safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%s", myGlobals.dbPath, dp->d_name);
	  if (stat(buf, &fStat) == 0) {
	    RAND_add(&fStat, sizeof(fStat), (double)16.0);
	  }
	}
      }
      closedir(directoryPointer);
    }

    if (RAND_status() == 0) {
      traceEvent(CONST_TRACE_WARNING, "SSL_PRNG: Unsuccessfully initialized - https:// may not work.");
    } else {
      traceEvent(CONST_TRACE_INFO, "SSL_PRNG: Successfully initialized.");
    }
  } else {
    traceEvent(CONST_TRACE_INFO, "SSL_PRNG: Automatically initialized!");
  }

  for(idx=0; myGlobals.configFileDirs[idx] != NULL; idx++) {
    safe_snprintf(__FILE__, __LINE__, buf, sizeof(buf), "%s/%s", myGlobals.configFileDirs[idx], CONST_SSL_CERTF_FILENAME);

    revertSlashIfWIN32(buf, 0);

    if((fd = fopen(buf, "rb")) != NULL)
      break;
  }

  if(fd == NULL) {
    traceEvent(CONST_TRACE_WARNING,
	       "SSL: Unable to find certificate '%s'. SSL support has been disabled",
	       CONST_SSL_CERTF_FILENAME);
    return(-1);
  } else
    fclose(fd);


  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
#if (OPENSSL_VERSION_NUMBER < 0x00905100l)
  needs_openssl_095_or_later();
#endif
  meth = (SSL_METHOD*)SSLv23_server_method();
  myGlobals.ctx = SSL_CTX_new(meth);
  if (!myGlobals.ctx) {
    ntop_ssl_error_report("ssl_init-server_method");
    return(2);
  }

  SSL_CTX_set_options(myGlobals.ctx, SSL_OP_ALL); /* Enable the work-arounds */
  SSL_CTX_set_options(myGlobals.ctx, SSL_OP_NO_TLSv1); 

  if ((!SSL_CTX_load_verify_locations(myGlobals.ctx, NULL, NULL)) ||
      (!SSL_CTX_set_default_verify_paths(myGlobals.ctx))) {
    ntop_ssl_error_report("ssl_init-verify");
  }

  SSL_CTX_set_session_id_context(myGlobals.ctx,
				 (void*)&s_server_session_id_context,
				 sizeof s_server_session_id_context);

  SSL_CTX_set_client_CA_list(myGlobals.ctx,SSL_load_client_CA_file(NULL));

  if (SSL_CTX_use_certificate_file(myGlobals.ctx, buf, SSL_FILETYPE_PEM) <= 0) {
    ntop_ssl_error_report("ssl_init-use_cert");
    return(3);
  }

  if (SSL_CTX_use_PrivateKey_file(myGlobals.ctx, buf, SSL_FILETYPE_PEM) <= 0) {
    ntop_ssl_error_report("ssl_init-use_pvtkey");
    return(4);
  }

  if (!SSL_CTX_check_private_key(myGlobals.ctx)) {
    traceEvent(CONST_TRACE_ERROR, "Private key does not match the certificate public key");
    return(5);
  }

  myGlobals.sslInitialized=1;
  traceEvent(CONST_TRACE_INFO, "SSL initialized successfully");
  return(0);
}


/* ********************* */

static int init_ssl_connection(SSL *con) {
  int i;
  long verify_error;

  if(!myGlobals.sslInitialized) return(0);

  if ((i=SSL_accept(con)) <= 0) {
#ifdef DEBUG
    traceEvent(CONST_TRACE_INFO, "SSL_accept: %d", i);
#endif

    if (BIO_sock_should_retry(i))
      return(1);

    verify_error=SSL_get_verify_result(con);
    if (verify_error != X509_V_OK) {
      traceEvent(CONST_TRACE_WARNING, "verify error:%s", X509_verify_cert_error_string(verify_error));
    }
    else
      ntop_ssl_error_report("ssl_init_connection");

    return(0);
  }

#ifdef DEBUG
  {
    /* the following declarations are needed to put debug mode to work */
    X509 *peer;
    char *str, buf[BUFSIZ];
    peer=SSL_get_peer_certificate(con);

    if(peer != NULL) {
      traceEvent(CONST_TRACE_INFO, "Client certificate");
      X509_NAME_oneline(X509_get_subject_name(peer),buf,BUFSIZ);
      traceEvent(CONST_TRACE_INFO, "subject=%s",buf);
      X509_NAME_oneline(X509_get_issuer_name(peer),buf,BUFSIZ);
      traceEvent(CONST_TRACE_INFO, "issuer=%s",buf);
      X509_free(peer);
    }

    if (SSL_get_shared_ciphers(con,buf,BUFSIZ) != NULL)
      traceEvent(CONST_TRACE_INFO, "Shared ciphers:%s",buf);
    str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
    traceEvent(CONST_TRACE_INFO, "CIPHER is %s",(str != NULL)?str:"(NONE)");
    if (con->hit) traceEvent(CONST_TRACE_INFO, "Reused session-id");
    if (SSL_ctrl(con,SSL_CTRL_GET_FLAGS,0,NULL) &
	TLS1_FLAGS_TLS_PADDING_BUG)
      traceEvent(CONST_TRACE_WARNING, "Peer has incorrect TLSv1 block padding");
  }
#endif

  return(1);
}

/* ********************* */

int accept_ssl_connection(int fd) {
  int i;

  if(!myGlobals.sslInitialized) return(-1);

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if(myGlobals.ssl[i].ctx == NULL) {
      myGlobals.ssl[i].ctx = SSL_new(myGlobals.ctx);
      if (myGlobals.ssl[i].ctx==NULL)
	exit (1);
      SSL_clear(myGlobals.ssl[i].ctx);
      SSL_set_fd(myGlobals.ssl[i].ctx, fd);
      myGlobals.ssl[i].socketId = fd;

      if(!SSL_is_init_finished(myGlobals.ssl[i].ctx))
	init_ssl_connection(myGlobals.ssl[i].ctx);
      break;
    }
  }

  if(i<MAX_SSL_CONNECTIONS)
    return 1;
  else
    return -1;
}

/* ********************* */

SSL* getSSLsocket(int fd) {
  int i;

  if(!myGlobals.sslInitialized) return(NULL);

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if((myGlobals.ssl[i].ctx != NULL)
       && (myGlobals.ssl[i].socketId == fd)) {
      return(myGlobals.ssl[i].ctx);
    }
  }

  return(NULL);
}

/* ********************* */

int term_ssl_connection(int fd) {
  int i, rc = 0;

  if(!myGlobals.sslInitialized) return(0);

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if((myGlobals.ssl[i].ctx != NULL)
       && (myGlobals.ssl[i].socketId == fd)) {
      rc = close(myGlobals.ssl[i].socketId);
      SSL_free(myGlobals.ssl[i].ctx);
      myGlobals.ssl[i].ctx = NULL;
    }
  }

  return(rc);
}

/* ********************* */

void term_ssl(void) {
  int i;

  if(!myGlobals.sslInitialized) return;

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if(myGlobals.ssl[i].ctx != NULL) {
      close(myGlobals.ssl[i].socketId);
      SSL_free (myGlobals.ssl[i].ctx);
      myGlobals.ssl[i].ctx = NULL;
    }
  }

}

#endif
