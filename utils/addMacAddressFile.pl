#!/usr/bin/perl

# Specify the ntop.db file location
$ntop_db_file = "../ntop.db";

if($ARGV[0] eq "") {
  print "Usage: addMacAddressFile.pl <file name>\n";
  exit -1;
}

if(open(IN, "< $ARGV[0]")) {
  while(<IN>) {

    # Remove trailer '\n'
    if(substr($_, -1, 1) eq "\n") { chop($_); }
    
    ($mac, $value) = split (/\t/,$_);

    print "Adding $mac/$value\n";
    system("./addMacAddress $mac \"value\" $ntop_db_file");
  }
} else {
  print "FATAL ERROR: unable to read file $ARGV[0]\n";
}
