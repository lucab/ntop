#!/usr/bin/perl
#
# Copyright (C) 2001 Luca Deri <deri@ntop.org>
#
#   	        http://www.ntop.org/
#

#
# Description:
#
# This is a simple program that returns a GIF about
# a host location
#
# October 2001
#
use LWP::Simple;

if($ENV{QUERY_STRING_UNESCAPED} ne "") {
  # Remove backslashes
  $ENV{QUERY_STRING_UNESCAPED} =~ s/\\//g;
  @in = split(/[&;]/,$ENV{QUERY_STRING_UNESCAPED});
} else {
  @in = split(/[&;]/,$ENV{QUERY_STRING});
}

foreach $i (0 .. $#in) {
  # Convert plus to space
  $in[$i] =~ s/\+/ /g;

  # Split into key and value.
  ($key, $val) = split(/=/,$in[$i],2); # splits on the first =.

  # Convert %XX from hex numbers to alphanumeric
  $key =~ s/%([A-Fa-f0-9]{2})/pack("c",hex($1))/ge;
  $val =~ s/%([A-Fa-f0-9]{2})/pack("c",hex($1))/ge;

  # Associate key and value
  $in{$key} .= "\0" if (defined($in{$key})); # \0 is the multiple separator
  $in{$key} .= $val;
}

$debug = 0;

$theHost = $in{host};

if($theHost eq "") { $theHost = "131.114.21.10"; }
#$theHost = "17.254.0.91";
if($debug) {
$theHost = "212.171.49.54";
}

$URL = "http://netgeo.caida.org/perl/netgeo.cgi?target=".$theHost."&method=getLatLong&nonblocking=true";

$content = get($URL);


if($content eq "") {
  print "No data. Please make sure ntop is up and running\n";
} else {
  # now let's print the raw output

    @rows = split(/\n/, $content);

    for($i=0; $i<$#rows; $i++) {
	if($debug) { print $i.") ".$rows[$i]."\n"; }
	if($rows[$i] =~  /(\S*):( *)(.*)<br>/) {
	    #print $1." = ".$3. "\n";
	    $elem{$1} = $3;
	}
    }
    
    $URL1 = "http://146.101.249.88/M4/gif.cgi?scale=500000&lon=".$elem{LONG}."&lat=".$elem{LAT}."&width=320&height=200";


    if(!$debug) { $content1 = get($URL1); }

    print "Content-type: image/gif\n\n";
    print $content1."\n";

    if($debug) {
	print $URL."\n";
	print $URL1."\n";
    }
}
