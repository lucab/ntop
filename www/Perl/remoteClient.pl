#!/usr/bin/perl
# 
# Copyright (C) 2001 Luca Deri <deri@ntop.org>
#
#   	        http://www.ntop.org/
#

#
# Description:
#
# This is a simple program that shows how to
# fetch information out of ntop
#
# January 2001
#
use LWP::Simple;

$ntopHost = "localhost";
$ntopPort = 3000;


$URL = "http://".$ntopHost.":".$ntopPort."/dumpData.html?language=perl";

$content = get($URL);


if($content eq "") {
  print "No data. Please make sure ntop is up and running\n";
} else {
  # evaluate the hash table
  %hash = eval($content);
  
  # %hash now contains the received entries
  
  while (($key, $value) = each %hash) {
    print $key."\n";
  }
  
  
  # now let's print the raw output
  
  print "==========================\n";
  print $content."\n";
  print "==========================\n";
}
