#!/usr/bin/perl
use strict;
use warnings;

use Net::Frame::ETH;
use Net::Frame::IPv4;
use Net::Frame::TCP;

my $eth = Net::Frame::ETH->new;
my $ip4 = Net::Frame::IPv4->new;
my $tcp = Net::Frame::TCP->new(
   options => "\x02\x04\x54\x0b",
);

$tcp->computeLengths;
$tcp->computeChecksums({
   type => 'IPv4',
   src  => $ip4->src,
   dst  => $ip4->dst,
});

$ip4->computeLengths({ payloadLength => $tcp->getLength });
$ip4->computeChecksums;

print $eth->print."\n";
print $ip4->print."\n";
print $tcp->print."\n";
