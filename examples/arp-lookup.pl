#!/usr/bin/perl
use strict;
use warnings;

use Net::Write::Layer2;
use Net::Frame::Device;
use Net::Frame::Simple;
use Net::Frame::Dump;

use Net::Frame::ETH qw(:consts);
use Net::Frame::ARP;

my $oDevice = Net::Frame::Device->new(target => $ARGV[0]);

my $eth = Net::Frame::ETH->new(
   src  => $oDevice->mac,
   type => NP_ETH_TYPE_ARP,
);
my $arp = Net::Frame::ARP->new(
   src   => $oDevice->mac,
   srcIp => $oDevice->ip,
   dstIp => $ARGV[0],
);

my $oWrite = Net::Write::Layer2->new(
   dev => $oDevice->dev,
);

my $oDump = Net::Frame::Dump->new(
   dev => $oDevice->dev,
);
$oDump->start;

my $oSimple = Net::Frame::Simple->new(
   layers => [ $eth, $arp ],
);
$oWrite->open;
$oSimple->send($oWrite);
$oWrite->close;

until ($oDump->timeout) {
   if (my $recv = $oSimple->recv($oDump)) {
      print $recv->print."\n";
      last;
   }
}

$oDump->stop;
$oDump->clean;
