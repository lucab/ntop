// File : ntop.i
// Command: swig -perl5 ntop.i

%module ntop
%{
#include "ntop.h"
%}

// #include "ntop_perl.h"
void ntop_perl_sendString(char *str);
void ntop_perl_send_http_header(int mime_type, char *title);
void ntop_perl_send_html_footer();
void ntop_perl_loadHost();
void ntop_perl_getFirstHost(int actualDeviceId);
void ntop_perl_getNextHost(int actualDeviceId);
void ntop_perl_sendFile(char* fileName, int doNotUnlink);
HostTraffic* ntop_perl_findHostByNumIP(HostAddr hostIpAddress, short vlanId, int actualDeviceId);
HostTraffic* ntop_perl_findHostBySerial(HostSerial serial, int actualDeviceId);
HostTraffic* ntop_perl_findHostByMAC(char* macAddr, short vlanId, int actualDeviceId);
