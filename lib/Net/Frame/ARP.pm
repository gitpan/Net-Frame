#
# $Id: ARP.pm,v 1.2 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::ARP;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_ARP_HDR_LEN
      NP_ARP_HTYPE_ETH
      NP_ARP_PTYPE_IPv4
      NP_ARP_HSIZE_ETH
      NP_ARP_PSIZE_IPv4
      NP_ARP_OPCODE_REQUEST
      NP_ARP_OPCODE_REPLY
      NP_ARP_ADDR_BROADCAST
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_ARP_HDR_LEN        => 28;
use constant NP_ARP_HTYPE_ETH      => 0x0001;
use constant NP_ARP_PTYPE_IPv4     => 0x0800;
use constant NP_ARP_PTYPE_IPv6     => 0x86dd;
use constant NP_ARP_HSIZE_ETH      => 0x06;
use constant NP_ARP_PSIZE_IPv4     => 0x04;
use constant NP_ARP_OPCODE_REQUEST => 0x0001;
use constant NP_ARP_OPCODE_REPLY   => 0x0002;
use constant NP_ARP_ADDR_BROADCAST => '00:00:00:00:00:00';

our @AS = qw(
   hType
   pType
   hSize
   pSize
   opCode
   src
   srcIp
   dst
   dstIp
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

use Net::Frame::Utils qw(convertMac inetAton inetNtoa);

sub new {
   my $self = shift->SUPER::new(
      hType   => NP_ARP_HTYPE_ETH,
      pType   => NP_ARP_PTYPE_IPv4,
      hSize   => NP_ARP_HSIZE_ETH,
      pSize   => NP_ARP_PSIZE_IPv4,
      opCode  => NP_ARP_OPCODE_REQUEST,
      src     => '00:00:00:00:00:00',
      dst     => NP_ARP_ADDR_BROADCAST,
      srcIp   => '127.0.0.1',
      dstIp   => '127.0.0.1',
      @_,
   );

   $self->[$__src] = lc($self->[$__src]) if $self->[$__src];
   $self->[$__dst] = lc($self->[$__dst]) if $self->[$__dst];

   $self;
}

sub getLength { NP_ARP_HDR_LEN }

sub pack {
   my $self = shift;

   (my $srcMac = $self->[$__src]) =~ s/://g;
   (my $dstMac = $self->[$__dst]) =~ s/://g;

   $self->[$__raw] = $self->SUPER::pack('nnUUnH12a4H12a4',
      $self->[$__hType],
      $self->[$__pType],
      $self->[$__hSize],
      $self->[$__pSize],
      $self->[$__opCode],
      $srcMac,
      inetAton($self->[$__srcIp]),
      $dstMac,
      inetAton($self->[$__dstIp]),
   ) or return undef;

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($hType, $pType, $hSize, $pSize, $opCode, $srcMac, $srcIp, $dstMac,
      $dstIp, $payload) =
         $self->SUPER::unpack('nnUUnH12a4H12a4 a*', $self->[$__raw])
            or return undef;

   $self->[$__hType]  = $hType;
   $self->[$__pType]  = $pType;
   $self->[$__hSize]  = $hSize;
   $self->[$__pSize]  = $pSize;
   $self->[$__opCode] = $opCode;
   $self->[$__src]    = convertMac($srcMac);
   $self->[$__srcIp]  = inetNtoa($srcIp);
   $self->[$__dst]    = convertMac($dstMac);
   $self->[$__dstIp]  = inetNtoa($dstIp);

   $self->[$__payload] = $payload;

   $self;
}

sub match {
   my $self = shift;
   my ($with) = @_;
      ($self->[$__opCode] == NP_ARP_OPCODE_REQUEST)
   && ($with->[$__opCode] == NP_ARP_OPCODE_REPLY)
   && ($with->[$__dst]    eq $self->[$__src])
   && ($with->[$__srcIp]  eq $self->[$__dstIp])
   && ($with->[$__dstIp]  eq $self->[$__srcIp]);
}

sub encapsulate { NP_LAYER_NONE }

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf
      "$l: hType:0x%04x  pType:0x%04x  hSize:0x%02x  pSize:0x%02x".
      "  opCode:0x%04x\n".
      "$l: src:%s  srcIp:%s\n".
      "$l: dst:%s  dstIp:%s",
         $self->[$__hType], $self->[$__pType], $self->[$__hSize],
         $self->[$__pSize], $self->[$__opCode], $self->[$__src],
         $self->[$__srcIp], $self->[$__dst],  $self->[$__dstIp];
}

#
# Helpers
#

sub _isOpCode { shift->[$__opCode] == shift             }
sub isRequest { shift->_isOpCode(NP_ARP_OPCODE_REQUEST) }
sub isReply   { shift->_isOpCode(NP_ARP_OPCODE_REPLY)   }

1;

__END__

=head1 NAME

Net::Frame::ARP - Address Resolution Protocol layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:arp);
   require Net::Packet::ARP;

   # Build a layer
   my $layer = Net::Packet::ARP->new(
      dstIp => "192.168.0.1",
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::ARP->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the ARP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc826.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer3> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<hType>

=item B<pType>

Hardware and protocol address types.

=item B<hSize>

=item B<pSize>

Hardware and protocol address sizes in bytes.

=item B<opCode>

The operation code number to perform.

=item B<src>

=item B<dst>

Source and destination hardware addresses.

=item B<srcIp>

=item B<dstIp>

Source and destination IP addresses.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

hType:  NP_ARP_HTYPE_ETH

pType:  NP_ARP_PTYPE_IPv4

hSize:  NP_ARP_HSIZE_ETH

pSize:  NP_ARP_PSIZE_IPv4

opCode: NP_ARP_OPCODE_REQUEST

src:    $Env->mac

dst:    NP_ARP_ADDR_BROADCAST

srcIp:  $Env->ip

dstIp:  127.0.0.1

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<isRequest>

=item B<isReply>

Returns 1 if the B<opCode> attribute is of specified type.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:arp);

=over 4

=item B<NP_ARP_HTYPE_ETH>

=item B<NP_ARP_PTYPE_IPv4>

Hardware and protocol address types.

=item B<NP_ARP_HSIZE_ETH>

=item B<NP_ARP_PSIZE_IPv4>

Hardware and protocol address sizes.

=item B<NP_ARP_OPCODE_REQUEST>

=item B<NP_ARP_OPCODE_REPLY>

Operation code numbers.

=item B<NP_ARP_ADDR_BROADCAST>

Broadcast address for B<src> or B<dst> attributes.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
