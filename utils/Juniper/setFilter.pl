#!/usr/bin/perl -X

#####
#
# load_configuration.pl
#
#    description:
#
#        load the configuration from an xml file and report the result.
#
#####
use JUNOS::Device;
use JUNOS::Trace;
use Getopt::Std;
use Term::ReadKey;

#
# Define the constants used in this example
#
use constant REPORT_SUCCESS => 1;
use constant REPORT_FAILURE => 0;
use constant STATE_CONNECTED => 1;
use constant STATE_LOCKED => 2;
use constant STATE_CONFIG_LOADED => 3;


# print the usage of this script
sub output_usage
{
    my $usage = "Usage: $0 [options] <filter> <target>

Where:

  <filter>  juniper filter e.g. 'protocol [udp tcp icmp];'
  <target>  The hostname of the target router.

Options:

  -l <login>    A login name accepted by the target router.
  -p <password> The password for the login name.
  -t <template> The filter template (see below).
  -m <access>	Access method.  It can be clear-text, ssl, ssh or telnet.  Default: telnet.
  -d            turn on debug, full blast.

Notes:
  Users can omit -l, -p, -f using the /etc/juniper.conf configuration file.
  It contains configuration information with the following format:

  [USER]
  <username>

  [PASSWORD]
  <password>

  [FILTER]
  <filter>

  For instance:

  [USER]
  username

  [PASSWORD]
  password
  
  [FILTER]
  firewall {
    family inet {
    filter pcap {
      term mirroring {
  replace:
        from { \@filter\@ }
        then { sample; accept; }
      }
    }
   }
  }


  The \@filter\@ string is replaced with the filter the user specifies at command line.
";
    die $usage;
}

# grace_shutdown
# To gracefully shutdown.  Recognized 3 states:  1 connected, 2 locked, 
# 3 config_loaded
# Put eval around each step to make sure the next step is performed no
# matter what.
sub graceful_shutdown
{
    my ($jnx, $req, $state, $success) = @_;

    if ($state >= STATE_CONFIG_LOADED) {
        if($debug) { print "Rolling back configuration ...\n"; }
	eval {
            $jnx->load_configuration(rollback => 0);
	};
    }

    if ($state >= STATE_LOCKED) {
        if($debug) { print "Unlocking configuration database ...\n"; }
	eval {
            $jnx->unlock_configuration();
	};
    }

    if ($state >= STATE_CONNECTED) {
        if($debug) { print "Disconnecting from the router ...\n"; }
	eval {
	    $jnx->request_end_session();
            $jnx->disconnect();
	}
    }

    if ($success) {
        die "Filter set succesfully.\n";
    } else {
        die "Unable to set specified filter.\n";
    }
}

#
# escape special symbols in text
#
my %escape_symbols = (
                qq(")           => '&quot;',
                qq(>)           => '&gt;',
                qq(<)           => '&lt;',
                qq(')           => '&apos;',
                qq(&)           => '&amp;'
                );

# Create regex of these
my $char_class = join ("|", map { "($_)" } keys %escape_symbols);

sub get_escaped_text
{
    my $input_file = shift;
    my $input_string = "";

    open(FH, $input_file) or return undef;

    while(<FH>) {
	my $line = $_;
        $line =~ s/<configuration-text>//g;
        $line =~ s/<\/configuration-text>//g;
	$line =~ s/($char_class)/$escape_symbols{$1}/ge;
	$input_string .= $line;
    }

    return "<configuration-text>$input_string</configuration-text>";
}

#
# Set AUTOFLUSH to true
#
$| = 1;

# check arguments
my %opt;
getopts('l:p:dm:hta:t:', \%opt) || output_usage();
output_usage() if $opt{h};

# Check whether trace should be turned on
JUNOS::Trace::init(1) if $opt{d};

# The default configuration format is xml unless -t is specified
my $config_format = "xml";
$config_format = "text";

# The default action for load_configuration is 'merge'
my $load_action = "replace";
$load_action = $opt{a} if $opt{a};
use constant VALID_ACTIONS => "merge|replace|override";
output_usage() unless (VALID_ACTIONS =~ /$load_action/);

# Retrieve command line arguments
my $xmlfile = shift || output_usage();

# Retrieve host name
my $hostname = shift || output_usage();

# Retrieve the access method, can only be telnet or ssh.
my $access = $opt{m} || "telnet";
use constant VALID_ACCESSES => "telnet|ssh|clear-text|ssl";
output_usage() unless (VALID_ACCESSES =~ /$access/);

# Read /etc/juniper.conf
if(open(IN, "/etc/juniper.conf")) {
$opt{l} = "";
$opt{p} = "";
$opt{t} = "";


# Read /etc/juniper.conf
open(IN, "/etc/juniper.conf") || die "Unable to read file /etc/juniper.conf";
my $handleUser    = 0;
my $handlePass   = 0;
my $handleFilter = 0;

while(<IN>) {
    #print $_;
    if($_ =~ /^\#/)            { next; }
    elsif($_ =~ /^\[USER\]/)   { $handleUser   = 1; }
    elsif($_ =~ /^\[PASS/)     { $handlePass   = 1; }
    elsif($_ =~ /^\[FILTER\]/) { $handleFilter = 1; }
    else {
	if($handleFilter)  { $opt{t} .= $_; }
	elsif($handlePass) { $opt{p}    .= $_; }
	elsif($handleUser) { $opt{l}    .= $_; }
    }
}
close(IN);
if($opt{d}) {
    print "User:     $opt{l}";
    print "Password: $opt{p}";
    print "Filter:   $opt{t}";
}
$opt{l} =~ s/\n//g;
$opt{p} =~ s/\n//g;
chop($opt{t}); 
$opt{t} =~ s/\@filter\@/$xmlfile/ge;
}

if(($opt{l} eq "") || ($opt{p} eq "") || ($opt{t} eq "")) {
    print "Missing parameters. You need to either specify -l, -p, -t or\n".
	  "set this information into the /etc/juniper.conf file\n";
    exit(0);
}

# Check whether login name has been entered.  Otherwise prompt for it
my $login = "";
if ($opt{l}) {
    $login = $opt{l};
} else {
    print "login: ";
    $login = ReadLine 0;
    chomp $login;
}

# Check whether password has been entered.  Otherwise prompt for it
my $password = "";
if ($opt{p}) {
    $password = $opt{p};
} else {
    print "password: ";
    ReadMode 'noecho';
    $password = ReadLine 0;
    chomp $password;
    ReadMode 'normal';
    print "\n";
}

my %deviceinfo = (
        access => $access,
        login => $login,
        password => $password,
        hostname => $hostname,
    );

# Initialize the XML Parser
my $parser = new XML::DOM::Parser;

# connect TO the JUNOScript server
my $jnx = new JUNOS::Device(%deviceinfo);
unless ( ref $jnx ) {
    die "ERROR: $deviceinfo{hostname}: failed to connect.\n";
}

#
# Lock the configuration database before making any changes
# 
if($opt{d}) { print "Locking configuration database ...\n"; }
my $res = $jnx->lock_configuration();
my $err = $res->getFirstError();
if ($err) {
    print "ERROR: $deviceinfo{hostname}: failed to lock configuration.  Reason: $err->{message}.\n";
    graceful_shutdown($jnx, $xmlfile, STATE_CONNECTED, REPORT_FAILURE);
}


#
# Load the configuration
# 
my $doc;
my $xmlstring;

    $xmlstring = "<configuration-text>\n".$opt{t}."\n</configuration-text>";
    if($opt{d}) { print $xmlstring."\n"; }

    $doc = $parser->parsestring($xmlstring) if $xmlstring;
unless ( ref $doc ) {
    print "ERROR: Cannot parse $xmlfile, check to make sure the XML data is well-formed\n";
    graceful_shutdown($jnx, $xmlfile, STATE_LOCKED, REPORT_FAILURE);
}

#
# Put the load_configuration in an eval block to make sure if the rpc-reply
# has any parsing errors, the grace_shutdown will still take place.  Do
# not leave the database in an exclusive lock state.
#
eval {
    $res = $jnx->load_configuration(
	    format => $config_format, 
	    action => $load_action,
	    configuration => $doc);
};
if ($@) {
    print "ERROR: Failed to load the configuration from $xmlfile.   Reason: $@\n";
    graceful_shutdown($jnx, $xmlfile, STATE_CONFIG_LOADED, REPORT_FAILURE);
    exit(1);
} 

unless ( ref $res ) {
    print "ERROR: Failed to load the configuration from $xmlfile\n";
    graceful_shutdown($jnx, $xmlfile, STATE_LOCKED, REPORT_FAILURE);
}

$err = $res->getFirstError();
if ($err) {
    print "ERROR: Failed to load the configuration.  Reason: $err->{message}\n";
    graceful_shutdown($jnx, $xmlfile, STATE_CONFIG_LOADED, REPORT_FAILURE);
}

#
# Commit the change
#
if($opt{d}) { print "Commiting configuration from $xmlfile ...\n"; }
$res = $jnx->commit_configuration();
$err = $res->getFirstError();
if ($err) {
    print "ERROR: Failed to commit configuration.  Reason: $err->{message}.\n";
    graceful_shutdown($jnx, $xmlfile, STATE_CONFIG_LOADED, REPORT_FAILURE);
}

#
# Cleanup
#
graceful_shutdown($jnx, $xmlfile, STATE_LOCKED, REPORT_SUCCESS);
