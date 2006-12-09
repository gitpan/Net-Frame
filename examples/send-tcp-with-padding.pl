#!/usr/bin/perl
use strict;
use warnings;

my $target = shift || die("Specify target\n");

use Net::Frame::Device;
use Net::Frame::Simple;

use Net::Frame::ETH;
use Net::Frame::IPv4;
use Net::Frame::TCP;

my $oDevice = Net::Frame::Device->new(target => $target);

my $eth = Net::Frame::ETH->new(
   src => $oDevice->mac,
   dst => $oDevice->lookupMac($target),
);
my $ip4 = Net::Frame::IPv4->new(
   src => $oDevice->ip,
   dst => $target,
);
my $tcp = Net::Frame::TCP->new(
   options => "\x02\x04\x54\x0b",
);

my $oSimple = Net::Frame::Simple->new(
   layers => [ $eth, $ip4, $tcp ],
   padding => 'G'x2,
);

print $oSimple->print."\n";
print unpack('H*', $oSimple->raw)."\n";
