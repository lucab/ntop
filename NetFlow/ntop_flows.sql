

# phpMyAdmin MySQL-Dump
# version 2.3.0-rc3
# http://phpwizard.net/phpMyAdmin/
# http://www.phpmyadmin.net/ (download page)
#
# Host: localhost
# Generation Time: Jul 22, 2002 at 05:50 PM
# Server version: 3.23.49
# PHP Version: 4.1.2
# Database : `ntop`
# --------------------------------------------------------

#
# Table structure for table `flows`
#

CREATE TABLE flows (
  ipSrc varchar(19) NOT NULL default '',
  ipDst varchar(19) NOT NULL default '',
  pktSent int(11) NOT NULL default '0',
  bytesSent mediumint(9) NOT NULL default '0',
  startTime time NOT NULL default '00:00:00',
  endTime time NOT NULL default '00:00:00',
  srcPort smallint(6) NOT NULL default '0',
  dstPort smallint(6) NOT NULL default '0',
  tcpFlags tinyint(4) NOT NULL default '0',
  proto tinyint(4) NOT NULL default '0',
  tos tinyint(4) NOT NULL default '0'
) TYPE=MyISAM;

    


