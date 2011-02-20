#
# $Id: UDP.pm 333 2011-02-16 10:47:33Z gomor $
#
package Net::Frame::Layer::UDP;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts :subs);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NF_UDP_HDR_LEN
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NF_UDP_HDR_LEN => 8;

our @AS = qw(
   src
   dst
   length
   checksum
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

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
   ) or return;

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   # Pad it if less than the required length
   if (length($self->[$__raw]) < NF_UDP_HDR_LEN) {
      $self->[$__raw] .= ("\x00" x (NF_UDP_HDR_LEN - length($self->[$__raw])));
   }

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

sub getLength { NF_UDP_HDR_LEN }

sub computeLengths {
   my $self = shift;
   $self->[$__length] = $self->getLength + $self->getPayloadLength;
   return 1;
}

sub computeChecksums {
   my $self = shift;
   my ($layers) = @_;

   my $phpkt;
   for my $l (@$layers) {
      if ($l->layer eq 'IPv4') {
         $phpkt = $self->SUPER::pack('a4a4CCn',
            inetAton($l->src), inetAton($l->dst), 0, 17, $self->[$__length]);
         last;
      }
      elsif ($l->layer eq 'IPv6') {
         $phpkt = $self->SUPER::pack('a*a*NnCC',
            inet6Aton($l->src), inet6Aton($l->dst), $self->[$__length],
            0, 0, 17);
         last;
      }
   }

   $phpkt .= $self->SUPER::pack('nnnn',
      $self->[$__src], $self->[$__dst], $self->[$__length], 0)
         or return;

   my $last = $layers->[-1];
   if (defined($last->payload) && length($last->payload)) {
      $phpkt .= $self->SUPER::pack('a*', $last->payload)
         or return;
   }

   $self->[$__checksum] = inetChecksum($phpkt);

   return 1;
}

our $Next = {
   67   => 'DHCP',
   68   => 'DHCP',
   520  => 'RIPv1',
   1985 => 'HSRP',
};

sub encapsulate {
   my $self = shift;
   return $Next->{$self->[$__dst]} || $Next->{$self->[$__src]}
                                   || $self->[$__nextLayer];
}

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

Net::Frame::Layer::UDP - User Datagram Protocol layer object

=head1 SYNOPSIS

   use Net::Frame::Layer::UDP qw(:consts);

   # Build a layer
   my $layer = Net::Frame::Layer::UDP->new(
      src      => getRandomHighPort(),
      dst      => 0,
      length   => 0,
      checksum => 0,
   );
   $layer->pack;

   print 'RAW: '.$layer->dump."\n";

   # Read a raw layer
   my $layer = Net::Frame::Layer::UDP->new(raw = $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the UDP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc768.txt

See also B<Net::Frame::Layer> for other attributes and methods.

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

The following are inherited attributes. See B<Net::Frame::Layer> for more information.

=over 4

=item B<raw>

=item B<payload>

=item B<nextLayer>

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor. You can pass attributes that will overwrite default ones. See B<SYNOPSIS> for default values.

=item B<computeLengths>

Computes various lengths contained within this layer.

=item B<computeChecksums> ({ type => PROTO, src => IP, dst => IP })

In order to compute checksums of TCP, you need to pass the protocol type (IPv4, IPv6), the source and destination IP addresses (IPv4 for IPv4, IPv6 for IPv6).

=item B<getKey>

=item B<getKeyReverse>

These two methods are basically used to increase the speed when using B<recv> method from B<Net::Frame::Simple>. Usually, you write them when you need to write B<match> method.

=item B<match> (Net::Frame::Layer::UDP object)

This method is mostly used internally. You pass a B<Net::Frame::Layer::UDP> layer as a parameter, and it returns true if this is a response corresponding for the request, or returns false if not.

=back

The following are inherited methods. Some of them may be overriden in this layer, and some others may not be meaningful in this layer. See B<Net::Frame::Layer> for more information.

=over 4

=item B<layer>

=item B<computeLengths>

=item B<computeChecksums>

=item B<pack>

=item B<unpack>

=item B<encapsulate>

=item B<getLength>

=item B<getPayloadLength>

=item B<print>

=item B<dump>

=back

=head1 CONSTANTS

No constants here.

=head1 SEE ALSO

L<Net::Frame::Layer>

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2011, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
