#
# $Id: SLL.pm,v 1.6 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::SLL;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_SLL_HDR_LEN
      NP_SLL_PACKET_TYPE_SENT_BY_US
      NP_SLL_PACKET_TYPE_UNICAST_TO_US
      NP_SLL_ADDRESS_TYPE_512
      NP_SLL_PROTOCOL_USER
      NP_SLL_PROTOCOL_IPv4
      NP_SLL_PROTOCOL_X25
      NP_SLL_PROTOCOL_ARP
      NP_SLL_PROTOCOL_CGMP
      NP_SLL_PROTOCOL_80211
      NP_SLL_PROTOCOL_PPPIPCP
      NP_SLL_PROTOCOL_RARP
      NP_SLL_PROTOCOL_DDP
      NP_SLL_PROTOCOL_AARP
      NP_SLL_PROTOCOL_PPPCCP
      NP_SLL_PROTOCOL_WCP
      NP_SLL_PROTOCOL_8021Q
      NP_SLL_PROTOCOL_IPX
      NP_SLL_PROTOCOL_STP
      NP_SLL_PROTOCOL_IPv6
      NP_SLL_PROTOCOL_WLCCP
      NP_SLL_PROTOCOL_PPPoED
      NP_SLL_PROTOCOL_PPPoES
      NP_SLL_PROTOCOL_8021x
      NP_SLL_PROTOCOL_AoE
      NP_SLL_PROTOCOL_80211i
      NP_SLL_PROTOCOL_LLDP
      NP_SLL_PROTOCOL_LOOP
      NP_SLL_PROTOCOL_VLAN
      NP_SLL_PROTOCOL_PPPPAP
      NP_SLL_PROTOCOL_PPPCHAP
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_SLL_HDR_LEN                   => 16;
use constant NP_SLL_PACKET_TYPE_SENT_BY_US    => 4;
use constant NP_SLL_PACKET_TYPE_UNICAST_TO_US => 0;
use constant NP_SLL_ADDRESS_TYPE_512          => 512;
use constant NP_SLL_PROTOCOL_USER      => 0x0000;
use constant NP_SLL_PROTOCOL_IPv4      => 0x0800;
use constant NP_SLL_PROTOCOL_X25       => 0x0805;
use constant NP_SLL_PROTOCOL_ARP       => 0x0806;
use constant NP_SLL_PROTOCOL_CGMP      => 0x2001;
use constant NP_SLL_PROTOCOL_80211     => 0x2452;
use constant NP_SLL_PROTOCOL_PPPIPCP   => 0x8021;
use constant NP_SLL_PROTOCOL_RARP      => 0x8035;
use constant NP_SLL_PROTOCOL_DDP       => 0x809b;
use constant NP_SLL_PROTOCOL_AARP      => 0x80f3;
use constant NP_SLL_PROTOCOL_PPPCCP    => 0x80fd;
use constant NP_SLL_PROTOCOL_WCP       => 0x80ff;
use constant NP_SLL_PROTOCOL_8021Q     => 0x8100;
use constant NP_SLL_PROTOCOL_IPX       => 0x8137;
use constant NP_SLL_PROTOCOL_STP       => 0x8181;
use constant NP_SLL_PROTOCOL_IPv6      => 0x86dd;
use constant NP_SLL_PROTOCOL_WLCCP     => 0x872d;
use constant NP_SLL_PROTOCOL_PPPoED    => 0x8863;
use constant NP_SLL_PROTOCOL_PPPoES    => 0x8864;
use constant NP_SLL_PROTOCOL_8021x     => 0x888e;
use constant NP_SLL_PROTOCOL_AoE       => 0x88a2;
use constant NP_SLL_PROTOCOL_80211i    => 0x88c7;
use constant NP_SLL_PROTOCOL_LLDP      => 0x88cc;
use constant NP_SLL_PROTOCOL_LOOP      => 0x9000;
use constant NP_SLL_PROTOCOL_VLAN      => 0x9100;
use constant NP_SLL_PROTOCOL_PPPPAP    => 0xc023;
use constant NP_SLL_PROTOCOL_PPPCHAP   => 0xc223;

our @AS = qw(
   packetType
   addressType
   addressLength
   source
   protocol
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

sub new {
   shift->SUPER::new(
      packetType    => NP_SLL_PACKET_TYPE_SENT_BY_US,
      addressType   => NP_SLL_ADDRESS_TYPE_512,
      addressLength => 0,
      source        => 0,
      protocol      => NP_SLL_PROTOCOL_IPv4,
      @_,
   );
}

sub getLength { NP_SLL_HDR_LEN }

sub pack {
   my $self = shift;

   $self->[$__raw] = $self->SUPER::pack('nnnH16n',
      $self->[$__packetType],
      $self->[$__addressType],
      $self->[$__addressLength],
      $self->[$__source],
      $self->[$__protocol],
   ) or return undef;

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($pt, $at, $al, $s, $p, $payload) =
      $self->SUPER::unpack('nnnH16n a*', $self->[$__raw])
         or return undef;

   $self->[$__packetType]    = $pt;
   $self->[$__addressType]   = $at;
   $self->[$__addressLength] = $al;
   $self->[$__source]        = $s;
   $self->[$__protocol]      = $p;
   $self->[$__payload]       = $payload;

   $self;
}

sub encapsulate {
   my $types = {
      NP_SLL_PROTOCOL_IPv4()    => 'IPv4',
      NP_SLL_PROTOCOL_X25()     => 'X25',
      NP_SLL_PROTOCOL_ARP()     => 'ARP',
      NP_SLL_PROTOCOL_CGMP()    => 'CGMP',
      NP_SLL_PROTOCOL_80211()   => '80211',
      NP_SLL_PROTOCOL_PPPIPCP() => 'PPPIPCP',
      NP_SLL_PROTOCOL_RARP()    => 'RARP',
      NP_SLL_PROTOCOL_DDP ()    => 'DDP',
      NP_SLL_PROTOCOL_AARP()    => 'AARP',
      NP_SLL_PROTOCOL_PPPCCP()  => 'PPPCCP',
      NP_SLL_PROTOCOL_WCP()     => 'WCP',
      NP_SLL_PROTOCOL_8021Q()   => '8021Q',
      NP_SLL_PROTOCOL_IPX()     => 'IPX',
      NP_SLL_PROTOCOL_STP()     => 'STP',
      NP_SLL_PROTOCOL_IPv6()    => 'IPv6',
      NP_SLL_PROTOCOL_WLCCP()   => 'WLCCP',
      NP_SLL_PROTOCOL_PPPoED()  => 'PPPoED',
      NP_SLL_PROTOCOL_PPPoES()  => 'PPPoES',
      NP_SLL_PROTOCOL_8021x()   => '8021x',
      NP_SLL_PROTOCOL_AoE()     => 'AoE',
      NP_SLL_PROTOCOL_80211i()  => '80211i',
      NP_SLL_PROTOCOL_LLDP()    => 'LLDP',
      NP_SLL_PROTOCOL_LOOP()    => 'LOOP',
      NP_SLL_PROTOCOL_VLAN()    => 'VLAN',
      NP_SLL_PROTOCOL_PPPPAP()  => 'PPPPAP',
      NP_SLL_PROTOCOL_PPPCHAP() => 'PPPCHAP',
   };

   $types->{shift->[$__protocol]} || $self->[$__nextLayer];
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: packetType:0x%04x  addressType:0x%04x  ".
           "addressLength:0x%04x\n".
           "$l: source:%d  protocol:0x%04x",
      $self->[$__packetType], $self->[$__addressType],
      $self->[$__addressLength], $self->[$__source], $self->[$__protocol];
}

#
# Helpers
#

sub _isProtocol    { shift->[$__protocol] == shift()          }
sub isProtocolIpv4 { shift->_isProtocol(NP_SLL_PROTOCOL_IPv4) }
sub isProtocolIpv6 { shift->_isProtocol(NP_SLL_PROTOCOL_IPv6) }
sub isProtocolIp   {
   my $self = shift; $self->isProtocolIpv4 || $self->isProtocolIpv6;
}

1;

__END__

=head1 NAME

Net::Frame::SLL - Linux cooked capture layer object

=head1 SYNOPSIS

   #
   # Usually, you do not use this module directly
   #
   use Net::Packet::Consts qw(:sll);
   require Net::Packet::SLL;

   # Build a layer
   my $layer = Net::Packet::SLL->new;
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::SLL->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Linux cooked capture layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<packetType>

Stores the packet type (unicast to us, sent by us ...).

=item B<addressType>

The address type.

=item B<addressLength>

The length of the previously specified address.

=item B<source>

Source address.

=item B<protocol>

Encapsulated protocol.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

packetType:    NP_SLL_PACKET_TYPE_SENT_BY_US

addressType:   NP_SLL_ADDRESS_TYPE_512

addressLength: 0

source:        0

protocol:      NP_SLL_PROTOCOL_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isProtocolIpv4>

=item B<isProtocolIpv6>

=item B<isProtocolIp> - is type IPv4 or IPv6

Helper methods. Return true is the encapsulated layer is of specified type, false otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:sll);

=over 4

=item B<NP_SLL_PACKET_TYPE_SENT_BY_US>

=item B<NP_SLL_PACKET_TYPE_UNICAST_TO_US>

Various possible packet types.

=item B<NP_SLL_PROTOCOL_IPv4>

=item B<NP_SLL_PROTOCOL_IPv6>

=item B<NP_SLL_PROTOCOL_ARP>

=item B<NP_SLL_PROTOCOL_VLAN>

Various supported encapsulated layer types.

=item B<NP_SLL_HDR_LEN>

=item B<NP_SLL_ADDRESS_TYPE_512>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
