#
# $Id: UDP.pm,v 1.4 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::UDP;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_UDP_HDR_LEN
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_UDP_HDR_LEN => 8;

our @AS = qw(
   src
   dst
   length
   checksum
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

use Net::Frame::Utils qw(inetChecksum getRandomHighPort inetAton inet6Aton);

sub new {
   shift->SUPER::new(
      src      => getRandomHighPort(),
      dst      => 0,
      length   => 0,
      checksum => 0,
      @_,
   );
}

sub pack {
   my $self = shift;

   $self->[$__raw] = $self->SUPER::pack('nnnn',
      $self->[$__src],
      $self->[$__dst],
      $self->[$__length],
      $self->[$__checksum],
   ) or return undef;

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($src, $dst, $len, $checksum, $payload) =
      $self->SUPER::unpack('nnnn a*', $self->[$__raw])
         or return undef;

   $self->[$__src]      = $src;
   $self->[$__dst]      = $dst;
   $self->[$__length]   = $len;
   $self->[$__checksum] = $checksum;
   $self->[$__payload]  = $payload;

   $self;
}

sub getLength { NP_UDP_HDR_LEN }

sub getPayloadLength { shift->SUPER::getPayloadLength }

sub computeLengths {
   my $self = shift;
   $self->[$__length] = $self->getLength + $self->getPayloadLength;
   1;
}

sub computeChecksums {
   my $self = shift;
   my ($h)  = @_;

   my $phpkt;
   if ($h->{type} eq 'IPv4') {
      $phpkt = $self->SUPER::pack('a4a4CCn',
         inetAton($h->{src}), inetAton($h->{dst}), 0, 17, $self->[$__length],
      );
   }
   elsif ($h->{type} eq 'IPv6') {
      $phpkt = $self->SUPER::pack('a*a*NnCC',
         inet6Aton($h->{src}),
         inet6Aton($h->{dst}), $self->[$__length], 0, 0, 17,
      );
   }

   $phpkt .= $self->SUPER::pack('nnnn',
      $self->[$__src], $self->[$__dst], $self->[$__length], 0,
   ) or return undef;

   if ($self->[$__payload]) {
      $phpkt .= $self->SUPER::pack('a*', $self->[$__payload])
         or return undef;
   }

   $self->[$__checksum] = inetChecksum($phpkt);

   1;
}

sub encapsulate { NP_LAYER_NONE }

sub getKey {
   my $self = shift;
   $self->layer.':'.$self->[$__src].'-'.$self->[$__dst];
}

sub getKeyReverse {
   my $self = shift;
   $self->layer.':'.$self->[$__dst].'-'.$self->[$__src];
}

sub match {
   my $self = shift;
   my ($with) = @_;
   1;
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf
      "$l: src:%d  dst:%d  length:%d  checksum:0x%02x",
         $self->[$__src], $self->[$__dst], $self->[$__length],
         $self->[$__checksum];
}

1;

__END__

=head1 NAME

Net::Frame::UDP - User Datagram Protocol layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:udp);
   require Net::Packet::UDP;

   # Build a layer
   my $layer = Net::Packet::UDP->new(
      dst => 31222,
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::UDP->new(raw = $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the UDP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc768.txt

See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<src>

=item B<dst>

Source and destination ports.

=item B<length>

The length in bytes of the datagram, including layer 7 payload (that is, layer 4 + layer 7).

=item B<checksum>

Checksum of the datagram.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

src:      getRandomHighPort()

dst:      0

length:   0

checksum: 0

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<getPayloadLength>

Returns the length in bytes of payload (layer 7 object).

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
