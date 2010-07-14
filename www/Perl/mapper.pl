#!/usr/bin/perl -w
# ==========================================================================
#                               mapper.pl
#
#   A helper script to show host geographical position in ntop. A heavily-
#   modified version of www/Perl/mapper.pl to use www.geoplugin.net/xml.gp
#   intead of (the apparently defunct) netgeo.caida.org/perl/netgeo.cgi.
#
#   Unfortunately this script is heavy on dependencies, but fortunately
#   those should be part of most standard Perl toolkits: Data::Dumper,
#   CGI.pm, LWP::Simple, and XML::Simple.
#
#   Bugs:
#   * Error reporting is pretty non-specific, although most requests for
#     external resources (e.g., API calls) should generate errors in the
#     vicinity of where the attempt was made
#   * Since I'm using CGI.pm anyway, the URL parameter processing could
#     be done a lot more cleanly with CGI.pm.
#
#   TODO:
#   * Move any hard-coded URLs or "interesting"/configurable API
#     parameters to the top of the script where they can be easily
#     seen and modified.
#   * This script could do its work in a hundred fewer lines...
#   * Script needs more useful $DEBUGGING statements, if any at all. 
#
#   Author(s): Kevin M. Ernst <kernst+ntop@twentygrand.net>, July 2010
#              Luca Deri <deri@ntop.org>, 2001
#              as well as several other contributors
#
#   Older copyright notices and most of the original comments are left
#   intact, below. Any contributions made by Kevin Ernst may be considered
#   to be in the public domain, or under Luca's original license, whatever
#   that may have been.
#
# ==========================================================================

#
# Copyright (C) 2001 Luca Deri <deri@ntop.org>
#
#   	        http://www.ntop.org/
#
# Description:
#
# This is a simple program that returns a GIF about
# a host location
#
# October 2001
#
# NOTE
# The URL format changed:
# http://146.101.249.88/p/browse.cgi?scale=500000&lon=10.40&lat=43.72&width=320&height=200

use LWP::Simple;
use CGI qw(:standard :html3 div); # div isn't strictly supported by CGI.pm
use Data::Dumper;
use XML::Simple;
use strict;

my $DEBUGGING = 0;
my $SCRIPTNAME = `basename $0`;
my $DEBUGHOST = "212.171.49.54";
my $MAPSCALE  = 2000000;
my $css = <<END_OF_CSS;
	/*html {background:#151515}*/
	body { font-family:"Trebuchet MS", Arial, Helvetica, sans-serif	}
	a {outline:0; text-decoration:none}
	img {border:0}
	h1,h2,h3,h4,h5,h6 {font-weight:normal}
	div { border:2px solid; padding:0.3em; color:#dfdfdf; font-weight:bold;
	      text-align:center; font-size:large; }
	.fatal { border-color:#660000; background:#990000 }
	.warn  { border-color:#FF6633; background:#FF9900; color:black; }
	p.explanation { font-size: small; }
END_OF_CSS

# ===========================================================================
#                   M  A  I  N     P  R  O  G  R  A  M
# ===========================================================================
# The script proper begins here:
my ($host, @latlong);

unless ($host = &extract_host_from_query_string) {
	fatal_error("processing query string", __LINE__, "extract_host_from_query_string");
	die "Fatal error processing query string";
};
unless (@latlong = give_ip_latlong(isolate_ip_addr($host))) {
	fatal_error("retrieving lat/long for host $host", __LINE__, "give_ip_latlong");
	die "Fatal error retrieving lat/long for host";	
};
unless (emit_map_graphic(@latlong)) {
	fatal_error("retrieving map graphic", __LINE__, "emit_map_graphic");
	die "Fatal error retrieving map graphic";
};
exit 0;

# ===========================================================================
#                     S  U  B  R  O  U  T  I  N  E  S
# ===========================================================================
# Quick-and-dirty wrapper around emit_error_html():
sub fatal_error {
	my ($actionfailed, $lineno, $duringcallto) = @_;
	emit_error_html("fatal", "Script error in $SCRIPTNAME", "Error $actionfailed",
	  "A script error occurred at line $lineno while calling <tt>$duringcallto" . 
	  "()</tt>.<br><br>\nSorry it didn't work out.");
} # fatal_error

# Generic routine to produce sort-of-nice-looking HTML error pages:
sub emit_error_html {
	my ($severity, $title, $message, @explanation) = @_;
	# $type can either be "warning" or "fatal" (like, "this is never supposed
	# to happen"-fatal)
	print header('text/html'),
	      start_html(-title=>$title,
	                 -style=>{-code=>$css}, -id=>'content');
	for ($severity) {
		#/benign/ and do { print div({-class=>'note'},  $message); last; );
		/fatal/  and do { print div({-class=>'fatal'}, $message); last; };
		/warn/   and do { print div({-class=>'warn'},  $message); last; };
		# else
		print div({-class=>'fatal'}, "SCRIPT ERROR LINE #" . __LINE__);
		@explanation = "A bad value was passed to emit_error_html().<br>\n" .
		               "This should never happen.";
	} #for
	print p({-class=>'explanation'}, @explanation), end_html();
} # emit_error_html

# Process the query string and isolate just the target host part:
# (TODO: this should be rewritten to use CGI.pm, while we're at it...)
sub extract_host_from_query_string {
	my ($i, %in, @in, $key, $val, $theHost);
	
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

	$theHost = $in{host};

	# First of all, this shouldn't happen because 'ntop' should pass the
	# correct arguments to us.
	if($theHost eq "") {
		#$theHost = "131.114.21.10";
		#$theHost = "17.254.0.91";
		
		# kernst 2010-07-01: This is now an error, unless we're $DEBUGGING:
		if ($DEBUGGING) {
			$theHost = $DEBUGHOST;
		} else {
			return; # bad exit status, emit_error_html will handle
			        # returns 'undef' in scalar context, or '()' (empty list)
			        # in list context. See Cookbook #10.10.
		}
	}
	return $theHost;
} # sub process_query_string

# Isolate just the IP address part for further processing:
sub isolate_ip_addr {
	my $theHost = $_[0]; # first and only argument
	my ($item, @arr);
	
	# 17.08.2008 Ramon Schenkel <ramonschenkel@onlinehome.de>
	# Removes the domain to separate the IP-address:
	# split by @ char and store in array
	@arr = split (/@/, $theHost);

	# print each element of array
	foreach $item (@arr) {
		# drop the domain name
		$theHost=$item;
	}
	return $theHost;
} # sub isolate_ip_addr

# Returns an array (list) in order of (lat, long) given an IP as $_[0]:
sub give_ip_latlong {
	my $theHost = $_[0];
	my ($answer, $GEOURL, $geoxml);
	
	# The NetGeo service at caida.org doesn't work anymore. (At least on July
	# 1st, 2010 it didn't. Not for me.)
	#$URL = "http://netgeo.caida.org/perl/netgeo.cgi?target=" . 
	#       $theHost . "&method=getLatLong&nonblocking=true";
	
	# Use geoplugin.net instead:
	$GEOURL = "http://www.geoplugin.net/xml.gp?ip=$theHost";
	# TODO: move this to the top of the script with the rest of the globals.
	
	# Try to retrieve and parse the results as XML:
	unless ($answer = get($GEOURL))   { return };
	$geoxml = eval { XMLin($answer) };
	return if $@; # This is supposed to bomb out on badly-formed XML...
	              # I hope it works...
	if ($DEBUGGING) { print Dumper($geoxml); }

	if($geoxml eq "") {
		#print "ERROR: Nothing returned from geoplugin.net.\n";
		return;
	} elsif(not exists $geoxml->{geoplugin_latitude}) {
		# Whatever got returned wasn't the XML we were looking for.
		# Probably the stupid ISP hijacked the error page (looking at you,
		# RoadRunner)....
		return;
	}
	else {
		# Parse the old netgeo.caida.org output. This isn't used any more, but
		# I'm leaving the code and comments intact for posterity (kernst).
		# now let's print the raw output
		#@rows = split(/\n/, $content);

		#for($i=0; $i<$#rows; $i++) {
		#	if($DEBUGGING) {
		#		print $i.") ".$rows[$i]."\n";
		#	}
		#	if($rows[$i] =~  /(\S*):( *)(.*)<br>/) {
		#	    #print $1." = ".$3. "\n";
		#	    $elem{$1} = $3;
		#	}
		#}
			
		# Return (lat, long) in list context:	
		if (!$DEBUGGING) {
			return (sprintf("%0.2f", $geoxml->{geoplugin_latitude}),
					sprintf("%0.2f", $geoxml->{geoplugin_longitude}));
		} else {
			print "geoplugin.net returned the following for $theHost:\n";
			print "  lat  = $geoxml->{geoplugin_latitude}\n";
			print "  long = $geoxml->{geoplugin_longitude}\n\n";
			print "\$GEOURL = $GEOURL\n";
		}
	}
} # give_ip_latlong

# Returns image/gif for the given lat/long:
sub emit_map_graphic {
	my ($lat, $long) = @_;
	my ($MAPURL, $map);
	
	# Whatever this was, it probably hasn't worked since 2001...    
	# $URL1 = "http://146.101.249.88/M4/gif.cgi?scale=500000&lon=" .
	#   $elem{LONG} . "&lat=" . $elem{LAT} . "&width=320&height=200";

	# Fix courtesy of <ansa@hars.it>
	$MAPURL = "http://www.multimap.com/map/gif.cgi?scale=$MAPSCALE" .
	  '&db=ap&overviewmap=ap&lon=' . $long . '&lat=' . $lat . 
	  '&width=320&height=200&icon=blue';
	# TODO: move this to the top of the script with the rest of the globals.

	if(!$DEBUGGING) {
		$map = get($MAPURL) || return;
		unless (is_a_valid_gif($map)) { return };
		print "Content-type: image/gif\n\n";
		print $map;
	} else {
		print "\$MAPURL = $MAPURL\n\n";
	}
} #sub emit_map_graphic

# Sniff the first few bytes of a data stream to determine if what got
# returned is a genuine GIF87/89 file, or something like an "Error 404":
sub is_a_valid_gif {
	my $content = $_[0];
	$content =~ /^GIF8/ ? return 1 : return;
} # is_a_valid_gif


# End of mapper.pl
