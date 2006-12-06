#
# $Id: NULL.pm,v 1.4 2006/12/06 21:19:27 gomor Exp $
#
package Net::Frame::NULL;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_NULL_HDR_LEN
      NP_NULL_TYPE_USER
      NP_NULL_TYPE_IPv4
      NP_NULL_TYPE_IPv6
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_NULL_HDR_LEN   => 4;
use constant NP_NULL_TYPE_USER => 0x00000000;
use constant NP_NULL_TYPE_IPv4 => 0x02000000;
use constant NP_NULL_TYPE_IPv6 => 0x1c000000;

our @AS = qw(
   type
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

sub new {
   shift->SUPER::new(
      type => NP_NULL_TYPE_IPv4,
      @_,
   );
}

sub getLength { NP_NULL_HDR_LEN }

sub pack {
   my $self = shift;
   $self->[$__raw] = $self->SUPER::pack('N', $self->[$__type])
      or return undef;
   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($type, $payload) = $self->SUPER::unpack('N a*', $self->[$__raw])
      or return undef;

   $self->[$__type]    = $type;
   $self->[$__payload] = $payload;

   $self;
}

sub encapsulate {
   my $types = {
      NP_NULL_TYPE_IPv4() => 'IPv4',
      NP_NULL_TYPE_IPv6() => 'IPv6',
   };

   $types->{shift->[$__type]} || $self->[$__nextLayer];
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: type:0x%04x", $self->type;
}

1;

__END__

=head1 NAME

Net::Frame::NULL - BSD loopback layer object

=head1 SYNOPSIS

   #
   # Usually, you do not use this module directly
   #
   use Net::Packet::Consts qw(:null);
   require Net::Packet::NULL;

   # Build a layer
   my $layer = Net::Packet::NULL->new;
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::NULL->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the BSD loopback layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<type>

Stores the type of encapsulated layer.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

type: NP_NULL_TYPE_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<encapsulate>

=item B<getLength>

=item B<print>

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:null);

=over 4

=item B<NP_NULL_HDR_LEN>

NULL header length in bytes.

=item B<NP_NULL_TYPE_IPv4>

=item B<NP_NULL_TYPE_IPv6>

Various supported encapsulated layer types.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
