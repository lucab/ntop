#!/usr/bin/perl -w

#
# NetFlow V5 client that stores flows into a MySQl Database
# 
# Original Version
# (C) 2002 - Deri Luca <deri@ntop.org>
# 
# Modified Version (C) 2003 by
# sinma GmbH - Uli Staerk <uli@sinma.de>
# Berlin - Germany
#
# Prerequisites:
# - Perl
# - Perl DBI module (www.cpan.org)
# - Perl IO::Socket module (www.cpan.org)
# - Perl POSIX modules (www.cpan.org)
# - Perl NetAddr::IP module (www.cpan.org)
#
# Installation:
# - configure your NetFlow probes (ntop,nProbe,Cisco,...) to match the ip of the
#   machine this script will be running on. The default port it listens for flows
#   is UDP 2055
# - copy this script to any desired location in your directory tree
# - make this script executable (chmod)
# - check if the path to your perl executable in the first line of this script is correct
# - create the 'flows' table if you need it (read on)
#
# Usage:
# ./netFlowClient.pl
#
# This modified version does not only store the raw flows into a single
# table which will easily grow up to 2 gigs a day.
# 
# It creates a table for every month (machine time, not packet time - have to fix that)
# and in that table creates an entry for each host specified in a network list - every day.
# This makes it very easy to get traffic information for a specific host during a specific period
# 
# When a flow is coming in it gets checked weather it is coming or going to a host in
# the localnets list and the corresponding field for that host gets updated.
#
# The script produces almost no load at all on a dual P3 1000 with 2 G RAM and SCSI
# However the mysqld daemon might raise your load up to 0.04 on the same machine with
# 4096 hosts being monitored. Please read the mysql manual for performance tuning.
# Keep in mind that this might become a real problem when you have a lot of networks in your
# localnets list.
#
# According to my calculations each monthly table gets about 8 MB big when monitoring 4096 hosts
#
# TODO:
# - support other nets then /24
# - support other DBMS then MySQL
# - write local traffic to another table
# - find a way to have traffic-data for every 5 minutes in a reasonable amount of time and disk space
#
# Table layout for the 'flows' table:
#
# CREATE TABLE flows (
#  ipSrc varchar(19) NOT NULL default '',
#  ipDst varchar(19) NOT NULL default '',
#  pktSent int(11) NOT NULL default '0',
#  bytesSent mediumint(9) NOT NULL default '0',
#  startTime time NOT NULL default '00:00:00',
#  endTime time NOT NULL default '00:00:00',
#  srcPort smallint(6) NOT NULL default '0',
#  dstPort smallint(6) NOT NULL default '0',
#  tcpFlags tinyint(4) NOT NULL default '0',
#  proto tinyint(4) NOT NULL default '0',
#  tos tinyint(4) NOT NULL default '0'
# ) TYPE=MyISAM;


# This application has been strongly inspired by:
# ftp://ftp.mcs.anl.gov/pub/systems/software/netflowdb-0.1.0.tar.gz
#

use strict;
use DBI;
use IO::Socket;
use POSIX qw(strftime);
use NetAddr::IP;

my $debug = 0;				# prints A LOT OF debug messages (MySQL queries)
my $debug2 = 0;
my $rawFlows = 0;			# shall we dump the raw flows into the 'flows' table (don't forget to create it first!)? 1 = true, 0 = false
my $ignoreLocalTraffic = 1;		# shall we ignore traffic the host in our localnets have among each other? 1 = true, 0 = false

# array containing our local nets we want to get stored
# notice: only /24 nets (256 hosts) are supported at the moment.
# see the examples below for syntax.

my @ip = ('212.21.77.0',
	  '212.21.78.0',
	  '212.21.79.0',
	  '212.21.85.0',
	  '212.21.86.0',
	  '212.21.90.0',
	  '212.21.92.0',
	  '212.21.93.0',
	  '212.21.94.0',
	  '212.21.95.0',
	  '212.42.228.0',
	  '212.42.229.0',
	  '212.42.230.0',
	  '212.42.231.0',
	  '212.42.235.0',
	  '213.83.17.0');

# set your database parameters according to your needs

my $databaseName = "DBI:mysql:traffic"; # Database name
my $databaseUser = "traffic";           # Database user name
my $databasePw   = "traffic";           # Database user password

###################
#
# No need to edit anything below here.
#
###################

my @nets;

foreach(@ip) {
	my $temp=$_;
        my $tmp = new NetAddr::IP $temp;
        my $num = $tmp->numeric();
	push @nets,$num;
}

my $numHosts = scalar(@nets)*256;

my $numFlow = 0;
my $udpPort = 2055; # Default port

# Open a socket to receive Cisco netflow output packets
my $flows = IO::Socket::INET->new(Proto		=> "udp",
				  LocalAddr	=> "0.0.0.0",
				  LocalPort	=> "($udpPort)")
    || die "cannot open UDP socket listening @ port $udpPort";


my $dbh = DBI->connect($databaseName, $databaseUser, $databasePw) || die "Connect failed: $DBI::errstr\n";

print "Waiting for NetFlow V5 flows on port $udpPort\n";

my $first_time = strftime "%Y%m%d", localtime;
my $first_month = int($first_time/100);
my $now_time;
my $now_month;
my $run = 0;				# are we running yet? if not check if we should create any tables / data sets

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

    $now_time = strftime "%Y%m%d", localtime;
    $now_month = int($now_time/100);
    
    if($now_time!=$first_time || !$run) {		# check if date (year,month,day) changed
    	if($now_month!=$first_month || !$run) {		# if date changed check if month changed
		initializetable(1);			# create a new monthly table
		$first_month=$now_month;
	}
    	initializetable(2);				# create table entries for today
	$first_time=$now_time;
	$run = 1;					# from no on we only check for the tables when the date changed
    }
    
	      

    while(defined($aFlow)) # This loop ends 
    {
	if(length($aFlow) < 48) {   # This flow is too small
	    last; 
	} else {
	    my ($fsrc,$fdst,$fnext,$fin,$fout,$fpkts,$focts,$fstrt,$fend,$fsrcp,
		$fdstp,$ftcp,$fprot,$ftos,$fsas,$fdas,$fsmsk,$fdmsk) 
		= unpack("N3 n2 N4 n2 x C3 n2 C2 x2", $aFlow);
	    
	    if($rawFlows) {
		    my $sql = "INSERT INTO flows (ipSrc, ipDst, pktSent, bytesSent, startTime, endTime, srcPort, ".
		       	      "dstPort, tcpFlags, proto, tos) VALUES ('".num2ip($fsrc)."', '".num2ip($fdst)."', ".
	    		      "'$fpkts', '$focts', '".timestr($basetime+($fstrt/1000))."', '".timestr($basetime+($fend/1000)).
		    	      "', '$fsrcp', '$fdstp', '$ftcp', '$fprot', '$ftos')";
		    if($debug) { print $sql."\n"; }
		    $dbh->do($sql);
	    }

	    foreach(@nets) {				# check the incoming flow if one of the ip fields belongs to our local nets
	    	my $temp=$_;
		if (($fsrc&0xffffff00)==$temp) {	# source ip is in localnets, update bytesSent field
			if($ignoreLocalTraffic) {	# we don't count traffic the hosts in our network list have among each other
				my $inLocal = 0;
				foreach(@nets) {
					my $temp2=$_;
					if (($fdst&0xffffff00)==$temp2) {
						$inLocal = 1;		# destination ip is in our localnets list
						if($debug2) { print "Lokaler Traffic: Von: ".num2ip($fsrc)." Nach: ".num2ip($fdst)."\n"; }
					}
				}
				if(!$inLocal) {				# do the query if destionation ip is not in our localnets list
					my $sql2="UPDATE traffic_$now_month SET bytesSent=bytesSent+$focts WHERE ip='".num2ip($fsrc)."' AND date='$now_time';";
					$dbh->do($sql2);
					if($debug) { print $sql2."\n"; }
				}
			} else {
				my $sql2="UPDATE traffic_$now_month SET bytesSent=bytesSent+$focts WHERE ip='".num2ip($fsrc)."' AND date='$now_time';";
				$dbh->do($sql2);
				if($debug) { print $sql2."\n"; }
			}
		}
		if (($fdst&0xffffff00)==$temp) {	# destination ip is in localnets, update bytesRcvd field
			if($ignoreLocalTraffic) {	# we don't count traffic the hosts in our network list have among each other
				my $inLocal = 0;
				foreach(@nets) {
					my $temp2=$_;
					if (($fsrc&0xffffff00)==$temp2) {
						$inLocal = 1;		# source ip is in our localnets list
						if($debug2) { print "Lokaler Traffic: Von: ".num2ip($fsrc)." Nach: ".num2ip($fdst)."\n"; }
					}
				}
				if(!$inLocal) {				# do the query if source ip is not in our localnets list
					my $sql3="UPDATE traffic_$now_month SET bytesRcvd=bytesRcvd+$focts WHERE ip='".num2ip($fdst)."' AND date='$now_time';";
					$dbh->do($sql3);
					if($debug) { print $sql3."\n"; }
				}
			} else {
				my $sql3="UPDATE traffic_$now_month SET bytesRcvd=bytesRcvd+$focts WHERE ip='".num2ip($fdst)."' AND date='$now_time';";
				$dbh->do($sql3);
				if($debug) { print $sql3."\n"; }
			}
		}
	    }
	    
	    $numFlow++;
	}
	
	$aFlow=shift(@recvdFlow);
    }
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

#########################

sub initializetable {
    my $mode = shift(@_);
    if($mode==1) {							# create monthly table. mysql will check for us that the table doesn't exist yet. ugly.
	    my $query = "CREATE TABLE IF NOT EXISTS traffic_$now_month (
		         ip varchar(15) NOT NULL default '',
               		 bytesSent bigint(20) NOT NULL default '0',
		         bytesRcvd bigint(20) NOT NULL default '0',
			 date int(8) NOT NULL default '0',
			 PRIMARY KEY date (date,ip)
		         ) TYPE=MyISAM;";
			 # primary key date is an index over the date and ip fields which should make the update queries for each incoming flow much faster
			 # because it massively speeds up searching for the dataset specified in the WHERE clause
	    $dbh->do($query) or die "Failed to create monthly traffic table.";
    } elsif($mode==2) {							# create daily entries in monthly table
    	my $query2="SELECT count(DISTINCT ip) AS c FROM traffic_$now_month WHERE date='$now_time'";
	my $countHosts  = $dbh->selectrow_array($query2);
    	if($numHosts!=$countHosts) {					# only do if the hosts for $now_time don't exist yet. the script might come here when started for the second time on one day
	    foreach(@nets) {						# go through our network list and create an empty data set for each host
		    my $temp=$_;
		    for(my $i=$temp; $i<$temp+256; $i++) {
    			my $query3="INSERT IGNORE INTO traffic_$now_month VALUES('".num2ip($i)."',0,0,$now_time);";
			$dbh->do($query3);
		    }
	    }
	}
    }
}
