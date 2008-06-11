#
# (C) 2008 - Luca Deri <deri@ntop.org>
#

send_http_header();

my $i;

for($i=0; $i<10; $i++) {
    sendString("hello ".$i."\n");
}


########

sub my_send_http_header {
sendString("HTTP/1.0 200 OK\nCache-Control: no-cache\nExpires: 0\nConnection: close\nServer: ntop/3.3.6 (i686-apple-darwin9.3.0)\nContent-Type: text/html\n\n");
}

