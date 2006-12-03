#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::ETH;
use Net::Frame::IPv4;
use Net::Frame::TCP;
use Net::Frame::Simple;

my $eth = Net::Frame::ETH->new;
my $ip4 = Net::Frame::IPv4->new;
my $tcp = Net::Frame::TCP->new(
   options => "\x02\x04\x54\x0b",
);

my $oSimple = Net::Frame::Simple->new(
   layers => [ $eth, $ip4, $tcp ],
);

print $oSimple->print."\n";
print unpack('H*', $oSimple->raw)."\n";
