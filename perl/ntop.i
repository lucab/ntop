// File : ntop.i
// Command: swig -perl5 ntop.i

%module ntop
%{
  /* #include "ntop.h" */
%}

void sendString(char *str);
void send_http_header();