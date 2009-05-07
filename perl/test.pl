#
# (C) 2008 - Luca Deri <deri@ntop.org>
#

#use strict;
#use warnings;

send_http_header(1, "Known ntop hosts ".$ENV{'QUERY_STRING_UNESCAPED'});

# ---------------------------------------------

print "################################################\n";

getFirstHost(0);
loadHost();
while(($host{'ethAddress'} ne "") || ($host{'ipAddress'} ne ""))  {
    print "+ [ipAddress=",$host{'ipAddress'},"][macAddress=",$host{'macAddress'},"][pktSent/pktRcvd=",$host{'pktSent'},"/",$host{'pktRcvd'},"]\n";
    getNextHost(0);
    loadHost();
}

#for my $k1 ( sort keys %hosts ) {
#    print "k1: $k1\n";
#    for my $k2 ( keys %{$k1} ) {
#	print "k2: $k2 $hosts{ $k1 }{ $k2 }\n";
#    }
#}

#foreach $key (sort(keys %hosts{'a'})) {
#    print $key,"\n";
#}

#exit
# ---------------------------------------------

getFirstHost(0);
loadHost();

sendString("<center>\n");
sendString("<table border>\n");
sendString("<tr><th>MAC</th><th colspan=2>IP</th><th>Packets</th><th>Bytes</th></tr>\n");


while(($host{'ethAddress'} ne "") || ($host{'ipAddress'} ne ""))  {
    my $mac_addr;

    if($host{'ethAddress'} ne "") {
	my $mac = $host{'ethAddress'};
	$mac =~ tr/:/_/;
	$mac_addr = "<A HREF=/".$mac.".html>".$host{'ethAddress'}."</A>";
    } else {
	$mac_addr = "";
    }

    sendString("<tr><td>".$mac_addr
	       ."&nbsp;</td><td><A HREF=/".$host{'ipAddress'}.".html>".$host{'ipAddress'}."</A>"
	       ."&nbsp;</td><td>".$host{'hostResolvedName'}
	       ."&nbsp;</td><td> ".$host{'pktSent'}." / ".$host{'pktRcvd'}.""
	       ."&nbsp;</td><td> ".$host{'bytesSent'}." / ".$host{'bytesRcvd'}.""
	       ."&nbsp;</td></tr>\n");
    getNextHost(0);
    loadHost();
}

sendString("</table>\n");
sendString("</center>\n");
send_html_footer();

########

