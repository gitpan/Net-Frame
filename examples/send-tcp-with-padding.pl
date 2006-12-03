#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::Device;
use Net::Frame::Simple;

use Net::Frame::ETH;
use Net::Frame::IPv4;
use Net::Frame::TCP;

my $oDevice = Net::Frame::Device->new(target => $ARGV[0]);

my $eth = Net::Frame::ETH->new(
   src => $oDevice->mac,
   dst => $oDevice->lookupMac($ARGV[0]),
);
my $ip4 = Net::Frame::IPv4->new(
   src => $oDevice->ip,
   dst => $ARGV[0],
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
