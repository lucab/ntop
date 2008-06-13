#
# (C) 2008 - Luca Deri <deri@ntop.org>
#

send_http_header("Known hosts");

getFirstHost(0);
loadHost();

sendString("<center>\n");
sendString("<table border>\n");
sendString("<tr><th>MAC</th><th colspan=2>IP</th></tr>\n");

while(($host{'ethAddress'} ne "") 
      || ($host{'ipAddress'} ne ""))  {

    sendString("<tr><td>".$host{'ethAddress'}
	       ."&nbsp;</td><td>".$host{'ipAddress'}
	       ."&nbsp;</td><td>".$host{'hostResolvedName'}
	       ."&nbsp;</td></tr>\n");
    getNextHost(0);
    loadHost();
}

sendString("</table>\n");
sendString("</center>\n");

########

sub my_send_http_header {
sendString("HTTP/1.0 200 OK\nCache-Control: no-cache\nExpires: 0\nConnection: close\nServer: ntop/3.3.6 (i686-apple-darwin9.3.0)\nContent-Type: text/html\n\n");
}

