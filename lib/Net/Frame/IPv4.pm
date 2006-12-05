#
# $Id: IPv4.pm,v 1.6 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::IPv4;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_IPv4_HDR_LEN
      NP_IPv4_PROTOCOL_USER
      NP_IPv4_PROTOCOL_ICMPv4
      NP_IPv4_PROTOCOL_IGMPv4
      NP_IPv4_PROTOCOL_IPIP
      NP_IPv4_PROTOCOL_TCP
      NP_IPv4_PROTOCOL_EGP
      NP_IPv4_PROTOCOL_IGRP
      NP_IPv4_PROTOCOL_CHAOS
      NP_IPv4_PROTOCOL_UDP
      NP_IPv4_PROTOCOL_IDP
      NP_IPv4_PROTOCOL_DCCP
      NP_IPv4_PROTOCOL_IPv6
      NP_IPv4_PROTOCOL_IPv6ROUTING
      NP_IPv4_PROTOCOL_IPv6FRAGMENT
      NP_IPv4_PROTOCOL_IDRP
      NP_IPv4_PROTOCOL_RSVP
      NP_IPv4_PROTOCOL_GRE
      NP_IPv4_PROTOCOL_ESP
      NP_IPv4_PROTOCOL_AH
      NP_IPv4_PROTOCOL_ICMPv6
      NP_IPv4_PROTOCOL_EIGRP
      NP_IPv4_PROTOCOL_OSPF
      NP_IPv4_PROTOCOL_ETHERIP
      NP_IPv4_PROTOCOL_PIM
      NP_IPv4_PROTOCOL_VRRP
      NP_IPv4_PROTOCOL_STP
      NP_IPv4_PROTOCOL_SCTP
      NP_IPv4_MORE_FRAGMENT
      NP_IPv4_DONT_FRAGMENT
      NP_IPv4_RESERVED_FRAGMENT
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_IPv4_HDR_LEN           => 20;
use constant NP_IPv4_PROTOCOL_USER         => 0x00;
use constant NP_IPv4_PROTOCOL_ICMPv4       => 0x01;
use constant NP_IPv4_PROTOCOL_IGMPv4       => 0x02;
use constant NP_IPv4_PROTOCOL_IPIP         => 0x04;
use constant NP_IPv4_PROTOCOL_TCP          => 0x06;
use constant NP_IPv4_PROTOCOL_EGP          => 0x08;
use constant NP_IPv4_PROTOCOL_IGRP         => 0x09;
use constant NP_IPv4_PROTOCOL_CHAOS        => 0x10;
use constant NP_IPv4_PROTOCOL_UDP          => 0x11;
use constant NP_IPv4_PROTOCOL_IDP          => 0x16;
use constant NP_IPv4_PROTOCOL_DCCP         => 0x21;
use constant NP_IPv4_PROTOCOL_IPv6         => 0x29;
use constant NP_IPv4_PROTOCOL_IPv6ROUTING  => 0x2b;
use constant NP_IPv4_PROTOCOL_IPv6FRAGMENT => 0x2c;
use constant NP_IPv4_PROTOCOL_IDRP         => 0x2d;
use constant NP_IPv4_PROTOCOL_RSVP         => 0x2e;
use constant NP_IPv4_PROTOCOL_GRE          => 0x2f;
use constant NP_IPv4_PROTOCOL_ESP          => 0x32;
use constant NP_IPv4_PROTOCOL_AH           => 0x33;
use constant NP_IPv4_PROTOCOL_ICMPv6       => 0x3a;
use constant NP_IPv4_PROTOCOL_EIGRP        => 0x58;
use constant NP_IPv4_PROTOCOL_OSPF         => 0x59;
use constant NP_IPv4_PROTOCOL_ETHERIP      => 0x61;
use constant NP_IPv4_PROTOCOL_PIM          => 0x67;
use constant NP_IPv4_PROTOCOL_VRRP         => 0x70;
use constant NP_IPv4_PROTOCOL_STP          => 0x76;
use constant NP_IPv4_PROTOCOL_SCTP         => 0x84;
use constant NP_IPv4_MORE_FRAGMENT     => 1;
use constant NP_IPv4_DONT_FRAGMENT     => 2;
use constant NP_IPv4_RESERVED_FRAGMENT => 4;

our @AS = qw(
   id
   ttl
   src
   dst
   protocol
   checksum
   flags
   offset
   version
   tos
   length
   hlen
   options
   noFixLen
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);      

BEGIN {
   my $osname = {
      freebsd => [ \&_fixLenBsd, ],
      netbsd  => [ \&_fixLenBsd, ],
   };

   *_fixLen = $osname->{$^O}->[0] || \&_fixLenOther;
}

no strict 'vars';

use Carp;
use Net::Frame::Utils qw(getRandom16bitsInt inetAton inetNtoa inetChecksum);

sub _fixLenBsd   { pack('v', shift) }
sub _fixLenOther { pack('n', shift) }

sub new {
   shift->SUPER::new(
      version  => 4,
      tos      => 0,
      id       => getRandom16bitsInt(),
      length   => NP_IPv4_HDR_LEN,
      hlen     => 5,
      flags    => 0,
      offset   => 0,
      ttl      => 128,
      protocol => NP_IPv4_PROTOCOL_TCP,
      checksum => 0,
      src      => '127.0.0.1',
      dst      => '127.0.0.1',
      options  => '',
      noFixLen => 0,
      @_,
   );
}

sub pack {
   my $self = shift;

   # Thank you Stephanie Wehner
   my $hlenVer  = ($self->[$__hlen] & 0x0f)|(($self->[$__version] << 4) & 0xf0);
   my $flags    = $self->[$__flags];
   my $offset   = $self->[$__offset];

   my $len = ($self->[$__noFixLen] ? _fixLenOther($self->[$__length])
                                   : _fixLen($self->[$__length]));

   $self->[$__raw] = $self->SUPER::pack('CCa*nnCCna4a4',
      $hlenVer,
      $self->[$__tos],
      $len,
      $self->[$__id],
      $flags << 13 | $offset,
      $self->[$__ttl],
      $self->[$__protocol],
      $self->[$__checksum],
      inetAton($self->[$__src]),
      inetAton($self->[$__dst]),
   ) or return undef;

   my $opt;
   if ($self->[$__options]) {
      $opt = $self->SUPER::pack('a*', $self->[$__options])
         or return undef;
      $self->[$__raw] = $self->[$__raw].$opt;
   }

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($verHlen, $tos, $len, $id, $flags, $ttl, $proto, $cksum, $src, $dst,
      $payload) = $self->SUPER::unpack('CCnnnCCna4a4 a*', $self->[$__raw])
         or return undef;

   $self->[$__version]  = ($verHlen & 0xf0) >> 4;
   $self->[$__hlen]     = $verHlen & 0x0f;
   $self->[$__tos]      = $tos;
   $self->[$__length]   = $len;
   $self->[$__id]       = $id;
   $self->[$__flags]    = $flags >> 13;
   $self->[$__offset]   = $flags & 0x1fff;
   $self->[$__ttl]      = $ttl;
   $self->[$__protocol] = $proto;
   $self->[$__checksum] = $cksum;
   $self->[$__src]      = inetNtoa($src);
   $self->[$__dst]      = inetNtoa($dst);
   $self->[$__payload]  = $payload;

   my ($options, $payload2) = $self->SUPER::unpack(
      'a'. $self->getOptionsLength. 'a*', $self->[$__payload]
   ) or return undef;

   $self->[$__options] = $options;
   $self->[$__payload] = $payload2;

   $self;
}

sub getLength {
   my $self = shift;
   $self->[$__hlen] > 0 ? $self->[$__hlen] * 4 : 0;
}

sub getPayloadLength {
   my $self = shift;
   my $gLen = $self->getLength;
   $self->[$__length] > $gLen ? $self->[$__length] - $gLen : 0;
}

sub getOptionsLength {
   my $self = shift;
   my $gLen = $self->getLength;
   my $hLen = NP_IPv4_HDR_LEN;
   $gLen > $hLen ? $gLen - $hLen : 0;
}

sub computeLengths {
   my $self = shift;
   my ($h)  = @_;

   my $hLen = NP_IPv4_HDR_LEN;
   $hLen   += length($self->[$__options]) if $self->[$__options];
   $self->[$__hlen] = $hLen / 4;

   my $length = $self->getLength + $h->{payloadLength};
   $self->[$__length] = $length;

   1;
}

sub computeChecksums {
   my $self = shift;

   # Reset the checksum if already filled by a previous pack
   if ($self->[$__checksum]) {
      $self->[$__checksum] = 0;
   }

   $self->pack;
   $self->[$__checksum] = inetChecksum($self->[$__raw]);

   1;
}

sub encapsulate {
   my $types = {
      NP_IPv4_PROTOCOL_ICMPv4()       => 'ICMPv4',
      NP_IPv4_PROTOCOL_IGMPv4()       => 'IGMPv4',
      NP_IPv4_PROTOCOL_IPIP()         => 'IPIP',
      NP_IPv4_PROTOCOL_TCP()          => 'TCP',
      NP_IPv4_PROTOCOL_EGP()          => 'EGP',
      NP_IPv4_PROTOCOL_IGRP()         => 'IGRP',
      NP_IPv4_PROTOCOL_CHAOS()        => 'CHAOS',
      NP_IPv4_PROTOCOL_UDP()          => 'UDP',
      NP_IPv4_PROTOCOL_IDP()          => 'IDP',
      NP_IPv4_PROTOCOL_DCCP()         => 'DCCP',
      NP_IPv4_PROTOCOL_IPv6()         => 'IPv6',
      NP_IPv4_PROTOCOL_IPv6ROUTING()  => 'IPv6Routing',
      NP_IPv4_PROTOCOL_IPv6FRAGMENT() => 'IPv6Fragment',
      NP_IPv4_PROTOCOL_IDRP()         => 'IDRP',
      NP_IPv4_PROTOCOL_RSVP()         => 'RSVP',
      NP_IPv4_PROTOCOL_GRE()          => 'GRE',
      NP_IPv4_PROTOCOL_ESP()          => 'ESP',
      NP_IPv4_PROTOCOL_AH()           => 'AH',
      NP_IPv4_PROTOCOL_ICMPv6()       => 'ICMPv6',
      NP_IPv4_PROTOCOL_EIGRP()        => 'EIGRP',
      NP_IPv4_PROTOCOL_OSPF()         => 'OSPF',
      NP_IPv4_PROTOCOL_ETHERIP()      => 'ETHERIP',
      NP_IPv4_PROTOCOL_PIM()          => 'PIM',
      NP_IPv4_PROTOCOL_VRRP()         => 'VRRP',
      NP_IPv4_PROTOCOL_STP()          => 'STP',
      NP_IPv4_PROTOCOL_SCTP()         => 'SCTP',
   };

   $types->{shift->[$__protocol]} || $self->[$__nextLayer];
}

sub getKey {
   my $self  = shift;
   $self->layer.':'.$self->[$__src].'-'.$self->[$__dst];
}

sub getKeyReverse {
   my $self  = shift;
   $self->layer.':'.$self->[$__dst].'-'.$self->[$__src];
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf
      "$l: version:%d  hlen:%d  tos:0x%02x  length:%d  id:%d\n".
      "$l: flags:0x%02x  offset:%d  ttl:%d  protocol:0x%02x  checksum:0x%04x\n".
      "$l: src:%s  dst:%s",
         $self->[$__version], $self->[$__hlen], $self->[$__tos],
         $self->[$__length], $self->[$__id], $self->[$__flags],
         $self->[$__offset], $self->[$__ttl], $self->[$__protocol],
         $self->[$__checksum], $self->[$__src], $self->[$__dst];

   if ($self->[$__options]) {
      $buf .= sprintf "\n$l: $i: optionsLength:%d  options:%s",
         $self->getOptionsLength,
         CORE::unpack('H*', $self->[$__options]);
   }

   $buf;
}

#
# Helpers
#

sub _haveFlag  { (shift->[$__flags] & shift()) ? 1 : 0       }
sub haveFlagDf { shift->_haveFlag(NP_IPv4_DONT_FRAGMENT)     }
sub haveFlagMf { shift->_haveFlag(NP_IPv4_MORE_FRAGMENT)     }
sub haveFlagRf { shift->_haveFlag(NP_IPv4_RESERVED_FRAGMENT) }

sub _isProtocol      { shift->[$__protocol] == shift()             }
sub isProtocolTcp    { shift->_isProtocol(NP_IPv4_PROTOCOL_TCP)    }
sub isProtocolUdp    { shift->_isProtocol(NP_IPv4_PROTOCOL_UDP)    }
sub isProtocolIcmpv4 { shift->_isProtocol(NP_IPv4_PROTOCOL_ICMPv4) }
sub isProtocolIpv6   { shift->_isProtocol(NP_IPv4_PROTOCOL_IPv6)   }
sub isProtocolOspf   { shift->_isProtocol(NP_IPv4_PROTOCOL_OSPF)   }
sub isProtocolIgmpv4 { shift->_isProtocol(NP_IPv4_PROTOCOL_IGMPv4) }

1;

__END__
   
=head1 NAME

Net::Frame::IPv4 - Internet Protocol v4 layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:ipv4);
   require Net::Packet::IPv4;

   #�Build a layer
   my $ip = Net::Packet::IPv4->new(
      flags => NP_IPv4_DONT_FRAGMENT,
      dst   => "192.168.0.1",
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::IPv4->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the IPv4 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc791.txt
      
See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<id>

IP ID of the datagram.

=item B<ttl>

Time to live.

=item B<src>

=item B<dst>

Source and destination IP addresses.

=item B<protocol>

Of which type the layer 4 is.

=item B<checksum>

IP checksum.

=item B<flags>

IP Flags.

=item B<offset>

IP fragment offset.

=item B<version>

IP version, here it is 4.

=item B<tos>

Type of service flag.

=item B<length>

Total length in bytes of the packet, including IP headers (that is, layer 3 + layer 4 + layer 7).

=item B<hlen>

Header length in number of words, including IP options.

=item B<options>

IP options, as a hexadecimal string.

=item B<noFixLen>

Since the byte ordering of B<length> attribute varies from system to system, a subroutine inside this module detects which byte order to use. Sometimes, like when you build B<Net::Packet::VLAN> layers, you may have the need to avoid this. So set it to 1 in order to avoid fixing. Default is 0 (that is to fix).

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

version:  4

tos:      0

id:       getRandom16bitsInt()

length:   NP_IPv4_HDR_LEN

hlen:     5

flags:    0

offset:   0

ttl:      128

protocol: NP_IPv4_PROTOCOL_TCP

checksum: 0

src:      $Env->ip

dst:      "127.0.0.1"

options:  ""

noFixLen:   0

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1
 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<getHeaderLength>

Returns the header length in bytes, not including IP options.

=item B<getPayloadLength>

Returns the length in bytes of encapsulated layers (that is, layer 4 + layer 7).

=item B<getOptionsLength>

Returns the length in bytes of IP options.

=item B<haveFlagDf>

=item B<haveFlagMf>

=item B<haveFlagRf>

Returns 1 if the specified flag is set in B<flags> attribute, 0 otherwise.

=item B<isProtocolTcp>

=item B<isProtocolUdp>

=item B<isProtocolIpv6>

=item B<isProtocolOspf>

=item B<isProtocolIgmpv4>

=item B<isProtocolIcmpv4>

Returns 1 if the specified protocol is used at layer 4, 0 otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:ipv4);

=over 4

=item B<NP_IPv4_PROTOCOL_TCP>

=item B<NP_IPv4_PROTOCOL_UDP>

=item B<NP_IPv4_PROTOCOL_ICMPv4>

=item B<NP_IPv4_PROTOCOL_IPv6>

=item B<NP_IPv4_PROTOCOL_OSPF>

=item B<NP_IPv4_PROTOCOL_IGMPv4>

Various protocol type constants.

=item B<NP_IPv4_MORE_FRAGMENT>

=item B<NP_IPv4_DONT_FRAGMENT>

=item B<NP_IPv4_RESERVED_FRAGMENT>

Various possible flags.

=back

=head1 AUTHOR
   
Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret
      
You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut