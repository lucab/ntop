#!/usr/bin/perl -w

#
# NetFlow V5 client that stores flows into a MySQl Database
#
# (C) 2002 - Deri Luca <deri@ntop.org>
# 

# This application has been strongly inspired by:
# ftp://ftp.mcs.anl.gov/pub/systems/software/netflowdb-0.1.0.tar.gz
#

use strict;
use DBI;
use IO::Socket;


my $debug = 1;

###################

my $databaseName = "DBI:mysql:ntop"; # Database name
my $databaseUser = "root";           # Database user name
my $databasePw   = "";               # Database user password

###################

my $numFlow = 0;
my $udpPort = 2055; # Default port

# Open a socket to receive Cisco netflow output packets
my $flows = IO::Socket::INET->new(Proto		=> "udp",
				  LocalAddr	=> "0.0.0.0",
				  LocalPort	=> "($udpPort)")
    || die "cannot open UDP socket listening @ port $udpPort";


my $dbh = DBI->connect($databaseName, $databaseUser, $databasePw) || die "Connect failed: $DBI::errstr\n";

print "Waiting for NetFlow V5 flows on port $udpPort\n";

while(1) {
    my ($buf,$rcvval);
    $rcvval=$flows->recv($buf,2000,0) || die "recv: $!";

    if($debug) {
	printf "Received %d byte packet\n",length($buf);
    }

   # Flow header
    my @recvdFlow=unpack("a24 a48 a48 a48 a48 a48 a48 a48 a48 a48 a48 a48".
		     " a48 a48 a48 a48 a48 a48 a48 a48 a48 a48 a48".
		     " a48 a48 a48 a48 a48 a48 a48 a48",$buf);

    my ($hver,$hcount,$hsysuptime,$hunix_secs,$hunix_nsecs,$hflow_sequence)= unpack("n n N N N N x4",shift(@recvdFlow));

    next if ($hver != 5);                        # We handle NetFlow 5 only
    next if ($hcount != ((length($buf)-24)/48)); # This packet doesn't seem to be ok
    
    my $basetime=$hunix_secs+($hunix_nsecs/1000000000)-($hsysuptime/1000);

    my $aFlow=shift(@recvdFlow);

    while(defined($aFlow)) # This loop ends 
    {
	if(length($aFlow) < 48) {   # This flow is too small
	    last; 
	} else {
	    my ($fsrc,$fdst,$fnext,$fin,$fout,$fpkts,$focts,$fstrt,$fend,$fsrcp,
		$fdstp,$ftcp,$fprot,$ftos,$fsas,$fdas,$fsmsk,$fdmsk) 
		= unpack("N3 n2 N4 n2 x C3 n2 C2 x2", $aFlow);
	    
	    my $sql = "INSERT INTO flows (ipSrc, ipDst, pktSent, bytesSent, startTime, endTime, srcPort, ".
		"dstPort, tcpFlags, proto, tos) VALUES ('".num2ip($fsrc)."', '".num2ip($fdst)."', ".
		"'$fpkts', '$focts', '".timestr($basetime+($fstrt/1000))."', '".timestr($basetime+($fend/1000)).
		"', '$fsrcp', '$fdstp', '$ftcp', '$fprot', '$ftos')";
	
	    if($debug) { print $sql."\n"; }
	    
	    $dbh->do($sql);
	    $numFlow++;
	}
	
	$aFlow=shift(@recvdFlow);
    }
	
    #$dbh->commit();
} # while
    
$dbh->disconnect();

#########################

sub timestr {
    my $t=shift(@_);
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime($t);
    $mon++; # localtime() returns 0=Jan, 1=Feb, etc
    $year+=1900; # $year is the number of years since 1900,
    # that is, $year is 123 in year 2023.
    return(sprintf("%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d",$year,$mon,$mday,$hour,$min,$sec));
}

#########################

sub num2ip {
    my $a = shift(@_);
    return(sprintf("%d.%d.%d.%d",
		   ($a&0xff000000)>>24, ($a&0x00ff0000)>>16,
		   ($a&0x0000ff00)>>8, ($a&0x000000ff)));
}

