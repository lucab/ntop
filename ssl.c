/*
 *  Copyright (C) 1998-2001 Luca Deri <deri@ntop.org>
 *                          Portions by Stefano Suin <stefano@ntop.org>
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

#include "ntop.h"

#ifdef HAVE_OPENSSL

static SSL_CTX* ctx;

typedef struct ssl_connection {
  SSL* ctx;
  int  socketId;
} SSL_connection;

#define MAX_SSL_CONNECTIONS 32
static SSL_connection ssl[MAX_SSL_CONNECTIONS];

#define CERTF  "ntop-cert.pem"

#define CHK_NULL(x)    if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)   if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int verify_callback(int ok, X509_STORE_CTX *ctx);


int init_ssl(void) {
  int idx;
  FILE* fd=NULL;
  char     buf [384];
  SSL_METHOD *meth;
  int s_server_session_id_context = 1; /* anything will do */
  
  sslInitialized = 0;

  if(sslPort == 0) 
    return(0); /* The user decided NOT to use SSL */

  memset(ssl, 0, sizeof(ssl));

  for(idx=0; configFileDirs[idx] != NULL; idx++) {    
    if(snprintf(buf, sizeof(buf), "%s/%s", configFileDirs[idx], CERTF) < 0) 
      traceEvent(TRACE_ERROR, "Buffer overflow!");

#ifdef WIN32
    i=0;
    while(buf[i] != '\0') {
      if(buf[i] == '/') buf[i] = '\\';
      i++;
    }
#endif	  
    if((fd = fopen(buf, "rb")) != NULL)
      break;
  }
  
  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "Unable to find SSL certificate '%s'. SSL support has been disabled\n",
	   CERTF);
    return(-1);
  } else
    fclose(fd);


  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv2_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    return(2);
  }

  /* SSL_CTX_set_options(ctx,0); */

  
  if ((!SSL_CTX_load_verify_locations(ctx, NULL, NULL)) ||
      (!SSL_CTX_set_default_verify_paths(ctx))) {
      ERR_print_errors_fp(stderr);
    }

  SSL_CTX_set_session_id_context(ctx,
				 (void*)&s_server_session_id_context,
				 sizeof s_server_session_id_context);
  
  SSL_CTX_set_client_CA_list(ctx,SSL_load_client_CA_file(NULL));
    
  if (SSL_CTX_use_certificate_file(ctx, buf, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return(3);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, buf, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return(4);
  }
    
  if (!SSL_CTX_check_private_key(ctx)) {
    traceEvent(TRACE_WARNING, "Private key does not match the certificate public key\n");
    return(5);
  }

  sslInitialized=1;
  return(0);
}

/* ********************* */

static int init_ssl_connection(SSL *con)
{
  int i;
  long verify_error;

  if(!sslInitialized) return(0);

  if ((i=SSL_accept(con)) <= 0) {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "SSL_accept: %d\n", i);
#endif
      
    if (BIO_sock_should_retry(i))
      return(1);
      
    verify_error=SSL_get_verify_result(con);
    if (verify_error != X509_V_OK) {
      traceEvent(TRACE_WARNING, "verify error:%s\n", X509_verify_cert_error_string(verify_error));
    }
    else
      ERR_print_errors_fp(stderr);
      
    return(0);
  }

#ifdef DEBUG
  {
    /* the following declarations are needed to put debug mode to work */
    X509 *peer;
    char *str, buf[BUFSIZ];
    peer=SSL_get_peer_certificate(con);

    if(peer != NULL) {
      traceEvent(TRACE_INFO, "Client certificate\n");
      X509_NAME_oneline(X509_get_subject_name(peer),buf,BUFSIZ);
      traceEvent(TRACE_INFO, "subject=%s\n",buf);
      X509_NAME_oneline(X509_get_issuer_name(peer),buf,BUFSIZ);
      traceEvent(TRACE_INFO, "issuer=%s\n",buf);
      X509_free(peer);
    }

    if (SSL_get_shared_ciphers(con,buf,BUFSIZ) != NULL)
      traceEvent(TRACE_INFO, "Shared ciphers:%s\n",buf);
    str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
    traceEvent(TRACE_INFO, "CIPHER is %s\n",(str != NULL)?str:"(NONE)");
    if (con->hit) traceEvent(TRACE_INFO, "Reused session-id\n");
    if (SSL_ctrl(con,SSL_CTRL_GET_FLAGS,0,NULL) &
	TLS1_FLAGS_TLS_PADDING_BUG)
      traceEvent(TRACE_WARNING, "Peer has incorrect TLSv1 block padding\n");
  }
#endif

  return(1);
}

/* ********************* */

int accept_ssl_connection(int fd) {
  int i;
  
  if(!sslInitialized) return(-1);

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if(ssl[i].ctx == NULL) {
      ssl[i].ctx = SSL_new(ctx);   
      CHK_NULL(ssl[i].ctx);
      SSL_clear(ssl[i].ctx);
      SSL_set_fd(ssl[i].ctx, fd);
      ssl[i].socketId = fd;

      if(!SSL_is_init_finished(ssl[i].ctx))
	init_ssl_connection(ssl[i].ctx);
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

  if(!sslInitialized) return(NULL);

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if((ssl[i].ctx != NULL) 
       && (ssl[i].socketId == fd)) {
      return(ssl[i].ctx);
    }
  }

  return(NULL);
}

/* ********************* */

void term_ssl_connection(int fd) {
  int i;

  if(!sslInitialized) return;

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if((ssl[i].ctx != NULL) 
       && (ssl[i].socketId == fd)) {
      close(ssl[i].socketId);
      SSL_free(ssl[i].ctx);
      ssl[i].ctx = NULL;
    }
  }
}

/* ********************* */

void term_ssl(void) {
  int i;

  if(!sslInitialized) return;

  for(i=0; i<MAX_SSL_CONNECTIONS; i++) {
    if(ssl[i].ctx != NULL) {
      close(ssl[i].socketId);
      SSL_free (ssl[i].ctx);
      ssl[i].ctx = NULL;
    }
  }

}

#else
;
#endif
