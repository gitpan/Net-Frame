#
# $Id: Layer.pm,v 1.7 2006/12/06 21:19:12 gomor Exp $
#
package Net::Frame::Layer;
use strict;
use warnings;

require Class::Gomor::Array;
require Exporter;
our @ISA = qw(Class::Gomor::Array Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_LAYER_NONE
      NP_LAYER_UNKNOWN
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_LAYER_NONE    => undef;
use constant NP_LAYER_UNKNOWN => 'UNKNOWN';

our @AS = qw(
   raw
   payload
   nextLayer
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

use Carp;

sub new { shift->SUPER::new(nextLayer => NP_LAYER_UNKNOWN, @_) }

sub layer {
   my $layer = ref(shift);
   $layer =~ s/^Net::Frame:://;
   $layer;
}

# XXX: may use some optimizations
sub pack {
   my $self = shift;
   my ($fmt, @args) = @_;
   my $res;
   eval { $res = CORE::pack($fmt, @args) };
   $@ ? do { carp("@{[ref($self)]}: unable to pack structure\n"); undef }
      : $res;
}

sub unpack {
   my $self = shift;
   my ($fmt, $arg) = @_;
   my @res;
   eval { @res = CORE::unpack($fmt, $arg) };
   $@ ? do { carp("@{[ref($self)]}: unable to unpack structure\n"); () }
      : @res;
}

sub getPayloadLength {
   my $self = shift;
   $self->payload ? length($self->payload) : 0;
}

sub encapsulate      { NP_LAYER_NONE                 }
sub computeLengths   { 1                             }
sub computeChecksums { 1                             }
sub print            { $self->layer.': to implement' }
sub getLength        { 0                             }

sub dump {
   my $self = shift;

   my $hex = CORE::unpack('H*', $self->raw);
   my $l = $self->layer;
   sprintf "$l: $hex";
}

1;

__END__

=head1 NAME

Net::Frame::Layer - base class for all layer objects

=head1 DESCRIPTION

This is the base class for B<Net::Packet::Layer2>, B<Net::Packet::Layer3>, B<Net::Packet::Layer4> and B<Net::Packet::Layer7> modules.

It just provides those layers with inheritable attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<raw>

Stores the raw layer (as captured from the network, or packed to send to network).

=item B<payload>

Stores what is not part of the layer, that is the encapsulated part to be decoded by upper layers.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<is>

Returns the string describing the layer type (example: 'IPv4').

=item B<layer>

Returns the string describing the layer number (example: 'L3' for IPv4).

=item B<encapsulate>

Returns the next layer type (parsed from payload). This is the same string as returned by B<is> method.

=item B<computeLengths>

=item B<computeChecksums>

Generally, when a layer is built, some attributes are not yet known until the full Net::Packet::Frame is assembled. Those methods computes various lengths and checksums attributes found in a specific layer. Return 1 on success, undef otherwise.

=item B<print>

Just returns a string in a human readable format describing attributes found in the layer.

=item B<dump>

Just returns a string in hexadecimal format which is how the layer appears on the network.

=item B<pack>

Will pack all attributes into raw network format. This method MUST be implemented into each supported layers.

=item B<unpack>

Will unpack raw network format to respective attributes. This method MUST be implemented into each supported layers.

=item B<getLength>

Returns the layer length in bytes.

=item B<getPayloadLength>

Returns the total length of remaining raw data in bytes (without calling layer length).

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:layer);

=over 4

=item B<NP_LAYER>

Base layer string.

=item B<NP_LAYER_ETH>

=item B<NP_LAYER_NULL>

=item B<NP_LAYER_RAW>

=item B<NP_LAYER_SLL>

Layer 2 strings.

=item B<NP_LAYER_ARP>

=item B<NP_LAYER_IPv4>

=item B<NP_LAYER_IPv6>

=item B<NP_LAYER_VLAN>

=item B<NP_LAYER_PPPoE>

=item B<NP_LAYER_PPP>

=item B<NP_LAYER_LLC>

Layer 3 strings.

=item B<NP_LAYER_TCP>

=item B<NP_LAYER_UDP>

=item B<NP_LAYER_ICMPv4>

=item B<NP_LAYER_PPPLCP>

=item B<NP_LAYER_CDP>

Layer 4 strings.

=item B<NP_LAYER_7>

Layer 7 string.

=item B<NP_LAYER_NONE>

=item B<NP_LAYER_UNKNOWN>

Other strings.

=item B<NP_LAYER_N_2>

=item B<NP_LAYER_N_3>

=item B<NP_LAYER_N_4>

=item B<NP_LAYER_N_7>

=item B<NP_LAYER_N_UNKNOWN>

Layer number N strings.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
