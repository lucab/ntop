#!/usr/bin/perl
# 
# David Moore <davem@mitre.org>
# 
# Description:
#
# Fetch information out of ntop and write it as a delimited ASCII flat file.
#
# March 2001
#   	        
# Currently set up to loop indefinitely to dump data in 1 minute cycles.
#
#        command line syntax     perl dumpflat.pl > ntopflat.txt
#
# Each record Line contains all associated elements unwrapped by concatenating the hash key names.
# Currently there are 163 identified keys. 
# The first line written is the delineated element name list. This will be 3000-4000 characters.
# Subsequent lines contain the delineated element values.
#
# Field element order is fixed by the order in the "@flatkeys" definition.
#
# Any new fields encountered not in the "@flatkeys" definition are 
# appended to the end of the record as "key=value" pairs.
# These may be subsequently added to the "@flatkeys" definition.
#
use LWP::Simple;

$ntopHost = "localhost";
$ntopPort = 3000;
$URL = "http://".$ntopHost.":".$ntopPort."/dumpData.html?language=perl";
$delimiter = "|";   #field delimiter

# Define all of the fields used as a key. (See ntop emitter.c for key names. Search on "el->"  to find key assignments.)
# Keys are flattened from hierarchical version by concatenating keys level names.  163 keys.
@flatkeys = qw(PRIMARY DUMPTIME hostNumIpAddress hostSymIpAddress firstSeen lastSeen minTTL maxTTL nbHostName nbDescr nbDomainName nbNodeType atNodeName atNetwork atNode ipxHostName pktSent pktReceived pktBroadcastSent bytesBroadcastSent pktMulticastSent pktMulticastRcvd bytesMulticastSent bytesSent bytesReceived bytesSentLocally bytesReceivedLocally bytesSentRemotely bytesReceivedFromRemote actualSentThpt actualRcvdThpt lastHourSentThpt lastHourRcvdThpt averageSentThpt averageRcvdThpt peakSentThpt peakRcvdThpt actualSentPktThpt actualRcvdPktThpt averageSentPktThpt averageRcvdPktThpt peakRcvdPktThpt tcpSentLocally tcpReceivedLocally tcpSentRemotely tcpReceivedFromRemote udpSentLocally udpReceivedLocally udpSentRemotely udpReceivedFromRemote icmpSent icmpReceived ospfSent ospfReceived igmpSent igmpReceived arp_rarpSent arp_rarpReceived appletalkSent appletalkReceived decnetSent decnetReceived dlcSent dlcReceived icmpMsgSent icmpMsgRcvd stpSent stpRcvd ipxSent ipxReceived netbiosSent netbiosReceived osiSent osiReceived pktDuplicatedAckSent pktDuplicatedAckRcvd qnxSent qnxReceived otherSent otherReceived securityHostPkts_synPktsSent securityHostPkts_synPktsRcvd securityHostPkts_rstPktsSent securityHostPkts_rstPktsRcvd securityHostPkts_rstAckPktsSent securityHostPkts_rstAckPktsRcvd IP_FTP_sentLocally IP_FTP_receivedLocally IP_FTP_sentRemotely IP_FTP_receivedFromRemote IP_HTTP_sentLocally IP_HTTP_receivedLocally IP_HTTP_sentRemotely IP_HTTP_receivedFromRemote IP_DNS_sentLocally IP_DNS_receivedLocally IP_DNS_sentRemotely IP_DNS_receivedFromRemote IP_Telnet_sentLocally IP_Telnet_receivedLocally IP_Telnet_sentRemotely IP_Telnet_receivedFromRemote IP_NBios-IP_sentLocally IP_NBios-IP_receivedLocally IP_NBios-IP_sentRemotely IP_NBios-IP_receivedFromRemote IP_Mail_sentLocally IP_Mail_receivedLocally IP_Mail_sentRemotely IP_Mail_receivedFromRemote IP_SNMP_sentLocally IP_SNMP_receivedLocally IP_SNMP_sentRemotely IP_SNMP_receivedFromRemote IP_NFS_sentLocally IP_NFS_receivedLocally IP_NFS_sentRemotely IP_NFS_receivedFromRemote IP_X11_sentLocally IP_X11_receivedLocally IP_X11_sentRemotely IP_X11_receivedFromRemote IP_SSH_sentLocally IP_SSH_receivedLocally IP_SSH_sentRemotely IP_SSH_receivedFromRemote IP_NEWS_sentLocally IP_NEWS_receivedLocally IP_NEWS_sentRemotely IP_NEWS_receivedFromRemote SENT_ICMP_ECHO SENT_ICMP_ECHOREPLY SENT_ICMP_UNREACH RCVD_ICMP_ECHO RCVD_ICMP_ECHOREPLY RCVD_ICMP_UNREACH securityPkts_synPktsSent securityPkts_synPktsRcvd securityPkts_rstPktsSent securityPkts_rstPktsRcvd securityPkts_rstAckPktsSent securityPkts_rstAckPktsRcvd securityPkts_synFinPktsSent securityPkts_synFinPktsRcvd securityPkts_finPushUrgPktsSent securityPkts_finPushUrgPktsRcvd securityPkts_nullPktsSent securityPkts_nullPktsRcvd securityPkts_ackScanSent securityPkts_ackScanRcvd securityPkts_xmasScanSent securityPkts_xmasScanRcvd securityPkts_finScanSent securityPkts_finScanRcvd securityPkts_nullScanSent securityPkts_nullScanRcvd securityPkts_rejectedTCPConnSent securityPkts_rejectedTCPConnRcvd securityPkts_establishedTCPConnSent securityPkts_establishedTCPConnRcvd securityPkts_udpToClosedPortSent securityPkts_udpToClosedPortRcvd ethAddressString);

#Print a header line
 $outstring =""; foreach $key (@flatkeys){ $outstring = $outstring.$key.$delimiter;} print $outstring."\n";


$runloop = 1;

while ($runloop){  	        #perpetual loop?
#  $runloop = 0;			#No, just once! uncomment to run just once.

$content = "";
$content = get($URL);

if($content eq "") {
  print "No data. Please make sure ntop is up and running\n";
} else {
  # evaluate the hash table
  %ntopHash = eval($content);
  
  $recordString = "";  	#clear record string
  
  # %ntopHash is a hierarchical complex hash of the received entries


  # Walk through all of the keys and build a flat file
  while (($key, $value) = each %ntopHash) {
  	
    if ($recordString ne '') {
      print $recordString."\n";   		#output previous record
      $recordString = '';    			#initialize new record to empty
      undef %flathash;   			#clear any leftover hash keys and contents     
      @flathash{@flatkeys} =("") x @flatkeys;	#initialize a non-heirarchical hash to empty contents.
    }
    
    #Primary record Starts
    $flathash{'PRIMARY'} = $key;		#PRIMARY record key value is the level 1 key name. (usually IP but sometimes ethernet for local hosts)
    ($Second, $Minute, $Hour,$Day,$Month, $Year) = gmtime(time);
    if ($Second < 10) {$Second = "0".$Second;}
    if ($Minute < 10) {$Minute = "0".$Minute;}
    if ($Hour < 10) {$Hour = "0".$Hour;}
    if ($Day < 10) {$Day = "0".$Day;}
    $Month = $Month + 1;
    if ($Month < 10) {$Month = "0".$Month;}
    $Year = $Year + 1900;
    $timestring = $Year."-".$Month."-".$Day."-".$Hour.":".$Minute.":".$Second;
    $flathash{'DUMPTIME'} = $timestring;	#Timestamp of dump request.  YYYY-MM-DD-hh:mm:ss
    
    $finalvalue = $value;					#value is alway empty or a hash
    %hash2 = %$value;
    
    while (($key2, $value2) = each %hash2) {
      $finalvalue = $value2;                    		#Hold value2 as it may or may not be another hash key
#      print "(2K) ".$key2."\n";
      %hash3 = %$value2;
      while (($key3, $value3) = each %hash3) {
         $finalvalue = $value3;					#Hold value3 as it may or may not be another hash key
#         print "(3K) ".$key3."\n";
         %hash4 = %$value3;
        while (($key4, $value4) = each %hash4) {
          $finalvalue = $value4;				#value 4 is never a hash key.  Maximum nest depth.
          $flathash{$key2."_".$key3."_".$key4} = $finalvalue;	#flathash key is concatenated hierarchical keys 2,3,&4 with underscores.
          $finalvalue = "";  					#clear for coming up from nested hierarchy.
           
        }
        if ($finalvalue ne '' && index($finalvalue, 'HASH(0x') < 0) {
          $flathash{$key2."_".$key3} = $finalvalue;		#flathash key is concatenated hierarchical keys 2&3 with underscores.
          $finalvalue = "";  					#clear for coming up from nested hierarchy.
        }
      }
      if ($finalvalue ne '' && index($finalvalue, 'HASH(0x') < 0) {
        $flathash{$key2} = $finalvalue;				#flathash key is hierarchical keys 2.
        $finalvalue = "";					#clear for coming up from nested hierarchy.
      }
    }
    
    # Build record string.  End of primary loop, construct a record string.
    foreach $key (@flatkeys){
     $recordString = $recordString.$flathash{$key}.$delimiter;	#fixed order record.
     delete $flathash{$key};					#remove each key after use to look for unaccounted for keys.
    }
    while (($keyX, $valueX) = each %flathash) {
      if (index($valueX, 'HASH(0x') < 0) {				#eliminate null hash keys
        $recordString = $recordString.$keyX."=".$valueX.$delimiter;	#append any unaccounted keys and values.
      }
    }	
    
  }

  if ($recordString ne '') {
    print $recordString."\n";   			#output last record
    $recordString = '';    				#initialize new record to empty        
    @flathash{@flatkeys} =("") x @flatkeys;		#initialize a non-heirarchical hash to empty contents.
  } 

}

  if ($runloop){sleep 60;}     #dump on 1 minute intervals. Don't wait to quit.   

# Debug
#   print "\n\n==========================\n";
#   print $content."\n";
#   print "\n\n==========================\n";


}  #end perpetual loop
