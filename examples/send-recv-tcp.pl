#!/usr/bin/perl
use strict;
use warnings;

use Net::Write::Layer3;
use Net::Frame::Simple;
use Net::Frame::Dump;

use Net::Frame::IPv4;
use Net::Frame::TCP;

my $ip4 = Net::Frame::IPv4->new;
my $tcp = Net::Frame::TCP->new(
   dst     => 22,
   options => "\x02\x04\x54\x0b",
   payload => 'test',
);

my $oWrite = Net::Write::Layer3->new(
   dst => '127.0.0.1',
);

my $oDump = Net::Frame::Dump->new(
   dev => 'lo',
);
$oDump->start;

my $oSimple = Net::Frame::Simple->new(
   layers => [ $ip4, $tcp ],
);
$oWrite->open;
$oSimple->send($oWrite);
$oWrite->close;

until ($oDump->timeout) {
   if (my $recv = $oSimple->recv($oDump)) {
      print "RECV:\n".$recv->print."\n";
      last;
   }
}

$oDump->stop;
$oDump->clean;
