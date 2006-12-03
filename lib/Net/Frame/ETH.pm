#
# $Id: ETH.pm,v 1.5 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::ETH;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_ETH_HDR_LEN
      NP_ETH_ADDR_BROADCAST
      NP_ETH_TYPE_USER
      NP_ETH_TYPE_IPv4
      NP_ETH_TYPE_X25
      NP_ETH_TYPE_ARP
      NP_ETH_TYPE_CGMP
      NP_ETH_TYPE_80211
      NP_ETH_TYPE_PPPIPCP
      NP_ETH_TYPE_RARP
      NP_ETH_TYPE_DDP
      NP_ETH_TYPE_AARP
      NP_ETH_TYPE_PPPCCP
      NP_ETH_TYPE_WCP
      NP_ETH_TYPE_8021Q
      NP_ETH_TYPE_IPX
      NP_ETH_TYPE_STP
      NP_ETH_TYPE_IPv6
      NP_ETH_TYPE_WLCCP
      NP_ETH_TYPE_PPPoED
      NP_ETH_TYPE_PPPoES
      NP_ETH_TYPE_8021x
      NP_ETH_TYPE_AoE
      NP_ETH_TYPE_80211i
      NP_ETH_TYPE_LLDP
      NP_ETH_TYPE_LOOP
      NP_ETH_TYPE_VLAN
      NP_ETH_TYPE_PPPPAP
      NP_ETH_TYPE_PPPCHAP
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_ETH_HDR_LEN        => 14;
use constant NP_ETH_ADDR_BROADCAST => 'ff:ff:ff:ff:ff:ff';
use constant NP_ETH_TYPE_USER      => 0x0000;
use constant NP_ETH_TYPE_IPv4      => 0x0800;
use constant NP_ETH_TYPE_X25       => 0x0805;
use constant NP_ETH_TYPE_ARP       => 0x0806;
use constant NP_ETH_TYPE_CGMP      => 0x2001;
use constant NP_ETH_TYPE_80211     => 0x2452;
use constant NP_ETH_TYPE_PPPIPCP   => 0x8021;
use constant NP_ETH_TYPE_RARP      => 0x8035;
use constant NP_ETH_TYPE_DDP       => 0x809b;
use constant NP_ETH_TYPE_AARP      => 0x80f3;
use constant NP_ETH_TYPE_PPPCCP    => 0x80fd;
use constant NP_ETH_TYPE_WCP       => 0x80ff;
use constant NP_ETH_TYPE_8021Q     => 0x8100;
use constant NP_ETH_TYPE_IPX       => 0x8137;
use constant NP_ETH_TYPE_STP       => 0x8181;
use constant NP_ETH_TYPE_IPv6      => 0x86dd;
use constant NP_ETH_TYPE_WLCCP     => 0x872d;
use constant NP_ETH_TYPE_PPPoED    => 0x8863;
use constant NP_ETH_TYPE_PPPoES    => 0x8864;
use constant NP_ETH_TYPE_8021x     => 0x888e;
use constant NP_ETH_TYPE_AoE       => 0x88a2;
use constant NP_ETH_TYPE_80211i    => 0x88c7;
use constant NP_ETH_TYPE_LLDP      => 0x88cc;
use constant NP_ETH_TYPE_LOOP      => 0x9000;
use constant NP_ETH_TYPE_VLAN      => 0x9100;
use constant NP_ETH_TYPE_PPPPAP    => 0xc023;
use constant NP_ETH_TYPE_PPPCHAP   => 0xc223;

our @AS = qw(
   dst
   src
   type
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

BEGIN {
   *length = \&type;
}

no strict 'vars';

use Net::Frame::Utils qw(convertMac);

sub new {
   my $self = shift->SUPER::new(
      src  => '00:00:00:00:00:00',
      dst  => NP_ETH_ADDR_BROADCAST,
      type => NP_ETH_TYPE_IPv4,
      @_,
   );

   $self->[$__src] = lc($self->[$__src]) if $self->[$__src];
   $self->[$__dst] = lc($self->[$__dst]) if $self->[$__dst];

   $self;
}

sub getLength { NP_ETH_HDR_LEN }

sub pack {
   my $self = shift;

   (my $dst = $self->[$__dst]) =~ s/://g;
   (my $src = $self->[$__src]) =~ s/://g;

   $self->[$__raw] = $self->SUPER::pack('H12H12n', $dst, $src, $self->[$__type])
      or return undef;

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($dst, $src, $type, $payload) =
      $self->SUPER::unpack('H12H12n a*', $self->[$__raw])
         or return undef;

   $self->[$__dst] = convertMac($dst);
   $self->[$__src] = convertMac($src);

   $self->[$__type]    = $type;
   $self->[$__payload] = $payload;

   $self;
}

sub encapsulate {
   my $self = shift;

   my $types = {
      NP_ETH_TYPE_IPv4()    => 'IPv4',
      NP_ETH_TYPE_X25()     => 'X25',
      NP_ETH_TYPE_ARP()     => 'ARP',
      NP_ETH_TYPE_CGMP()    => 'CGMP',
      NP_ETH_TYPE_80211()   => '80211',
      NP_ETH_TYPE_PPPIPCP() => 'PPPIPCP',
      NP_ETH_TYPE_RARP()    => 'RARP',
      NP_ETH_TYPE_DDP ()    => 'DDP',
      NP_ETH_TYPE_AARP()    => 'AARP',
      NP_ETH_TYPE_PPPCCP()  => 'PPPCCP',
      NP_ETH_TYPE_WCP()     => 'WCP',
      NP_ETH_TYPE_8021Q()   => '8021Q',
      NP_ETH_TYPE_IPX()     => 'IPX',
      NP_ETH_TYPE_STP()     => 'STP',
      NP_ETH_TYPE_IPv6()    => 'IPv6',
      NP_ETH_TYPE_WLCCP()   => 'WLCCP',
      NP_ETH_TYPE_PPPoED()  => 'PPPoED',
      NP_ETH_TYPE_PPPoES()  => 'PPPoES',
      NP_ETH_TYPE_8021x()   => '8021x',
      NP_ETH_TYPE_AoE()     => 'AoE',
      NP_ETH_TYPE_80211i()  => '80211i',
      NP_ETH_TYPE_LLDP()    => 'LLDP',
      NP_ETH_TYPE_LOOP()    => 'LOOP',
      NP_ETH_TYPE_VLAN()    => 'VLAN',
      NP_ETH_TYPE_PPPPAP()  => 'PPPPAP',
      NP_ETH_TYPE_PPPCHAP() => 'PPPCHAP',
   };

   # Is this a 802.3 layer ?
   if ($self->[$__type] <= 1500 && $self->[$__payload]) {
      my $payload = CORE::unpack('H*', $self->[$__payload]);
      if ($payload =~ /^aaaa/) {
         return 'LLC';
      }
      return NP_LAYER_UNKNOWN;
   }

   $types->{$self->[$__type]} || $self->[$__nextLayer];
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf "$l: dst:%s  src:%s  ", $self->[$__dst], $self->[$__src];

   if ($self->[$__type] <= 1500) {
      $buf .= sprintf "length:%d", $self->[$__type];
   }
   else {
      $buf .= sprintf "type:0x%04x", $self->[$__type];
   }

   $buf;
}

1;

__END__

=head1 NAME

Net::Frame::ETH - Ethernet/802.3 layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:eth);
   require Net::Packet::ETH;

   # Build a layer
   my $layer = Net::Packet::ETH->new(
      type => NP_ETH_TYPE_IPv6,
      dst  => "00:11:22:33:44:55",
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::ETH->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Ethernet/802.3 layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc894.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<src>

=item B<dst>

Source and destination MAC addresses, in classical format (00:11:22:33:44:55).

=item B<type>

The encapsulated layer type (IPv4, IPv6 ...) for Ethernet. Values for Ethernet types are greater than 1500. If it is less than 1500, you should use the B<length> attribute (which is an alias of this one), because the layer is considered a 802.3 one. See http://www.iana.org/assignments/ethernet-numbers .

=item B<length>

The length of the payload when this layer is a 802.3 one. This is the same attribute as B<type>, but you cannot use it when calling B<new> (you can only use it as an accessor after that).

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones.
Default values:

src:         $Env->mac (see B<Net::Packet::Env>)

dst:         NP_ETH_ADDR_BROADCAST

type/length: NP_ETH_TYPE_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isTypeArp>

=item B<isTypeIpv4>

=item B<isTypeIpv6>

=item B<isTypeIp> - is type IPv4 or IPv6

=item B<isTypeVlan>

=item B<isTypePppoe>

Helper methods. Return true is the encapsulated layer is of specified type, false otherwise. 

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:eth);

=over 4

=item B<NP_ETH_HDR_LEN>

Ethernet header length in bytes.

=item B<NP_ETH_ADDR_BROADCAST>

Ethernet broadcast address.

=item B<NP_ETH_TYPE_IPv4>

=item B<NP_ETH_TYPE_IPv6>

=item B<NP_ETH_TYPE_ARP>

=item B<NP_ETH_TYPE_VLAN>

=item B<NP_ETH_TYPE_PPPoE>

Various supported Ethernet types.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
