#
# $Id: RAW.pm,v 1.4 2006/12/06 21:19:48 gomor Exp $
#
package Net::Frame::RAW;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);
__PACKAGE__->cgBuildIndices;

our %EXPORT_TAGS = (
   consts => [],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

no strict 'vars';

sub pack {
   my $self = shift;
   $self->[$__raw] = '';
   $self->[$__raw];
}

sub unpack {
   my $self = shift;
   $self->[$__payload] = $self->[$__raw];
   $self;
}

sub encapsulate {
   my $self = shift;

   return NP_LAYER_NONE if ! $self->[$__payload];

   # With RAW layer, we must guess which type is the first layer
   my $payload = CORE::unpack('H*', $self->[$__payload]);

   # XXX: may not work on big-endian arch
   if ($payload =~ /^4/) {
      return 'IPv4';
   }
   elsif ($payload =~ /^6/) {
      return 'IPv6';
   }
   elsif ($payload =~ /^0001....06/) {
      return 'ARP';
   }

   $self->[$__nextLayer];
}

sub print {
   my $self = shift;
   my $l = $self->layer;
   "$l: empty";
}

1;

__END__

=head1 NAME

Net::Frame::RAW - empty layer object

=head1 SYNOPSIS
  
   #
   # Usually, you do not use this module directly
   #
   # No constants for RAW
   require Net::Packet::RAW;

   # Build a layer
   my $layer = Net::Packet::RAW->new;
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::RAW->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the raw layer 2.
 
See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 METHODS

=over 4

=item B<new>

Object constructor. No default values, because no attributes.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<encapsulate>

=item B<getLength>

=item B<print>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
