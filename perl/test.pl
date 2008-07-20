#
# (C) 2008 - Luca Deri <deri@ntop.org>
#

#use strict;
#use warnings;

send_http_header(1, "Known ntop hosts");

# --------------------------------------------- 

#loadHosts();

#while ( my ($key, $value) = each(%hosts) ) {
#    print "$key => $value\n";
#}

#foreach $key (sort(keys %hosts)) {
#    print "[key=", $key,"][value=", $hosts{$key}"\n";
#}

#exit
# ---------------------------------------------

getFirstHost(0);
loadHost();

sendString("<center>\n");
sendString("<table border>\n");
sendString("<tr><th>MAC</th><th colspan=2>IP</th><th>Packets</th><th>Bytes</th></tr>\n");


while(($host{'ethAddress'} ne "") 
      || ($host{'ipAddress'} ne ""))  {
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

