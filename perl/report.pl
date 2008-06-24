#
# The First Basic Report
# Cosimo Streppone <cosimo@cpan.org>
# 2006-03-14
#
# $Id: basic.pl 16 2006-03-27 16:51:09Z cosimo $

#use strict;
#use warnings;
use PDF::ReportWriter;

my $rw = PDF::ReportWriter->new();
my @data = ();


getFirstHost(0);
loadHost();
while(($host{'ethAddress'} ne "") || ($host{'ipAddress'} ne ""))  {
    push(@data, [ $host{'ethAddress'}, $host{'ipAddress'}, $host{'hostResolvedName'}, $host{'bytesSent'}, $host{'bytesRcvd'} ]);
    getNextHost(0);
    loadHost();
}

$rw->render_report('./perl/report/basic.xml', \@data);

# Produces `./basic.pdf', check xml to understand how

# 13 = PDF
send_http_header(13, "");
$rw->save();

sendFile("/tmp/basic.pdf", 0);

