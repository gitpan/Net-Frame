#
# $Id: PPP.pm,v 1.5 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::PPP;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_PPP_HDR_LEN
      NP_PPP_PROTOCOL_USER
      NP_PPP_PROTOCOL_IPv4
      NP_PPP_PROTOCOL_DDP
      NP_PPP_PROTOCOL_IPX
      NP_PPP_PROTOCOL_IPv6
      NP_PPP_PROTOCOL_CDP
      NP_PPP_PROTOCOL_PPPLCP
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_PPP_HDR_LEN         => 4;
use constant NP_PPP_PROTOCOL_USER   => 0x0000;
use constant NP_PPP_PROTOCOL_IPv4   => 0x0021;
use constant NP_PPP_PROTOCOL_DDP    => 0x0029;
use constant NP_PPP_PROTOCOL_IPX    => 0x002b;
use constant NP_PPP_PROTOCOL_IPv6   => 0x0057;
use constant NP_PPP_PROTOCOL_CDP    => 0x0207;
use constant NP_PPP_PROTOCOL_PPPLCP => 0xc021;

our @AS = qw(
   address
   control
   protocol
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

sub new {
   shift->SUPER::new(
      address  => 0xff,
      control  => 0x03,
      protocol => NP_PPP_PROTOCOL_IPv4,
      @_,
   );
}

sub getLength { NP_PPP_HDR_LEN }

sub pack {
   my $self = shift;

   $self->[$__raw] = $self->SUPER::pack('CCn', $self->[$__address],
      $self->[$__control], $self->[$__protocol])
         or return undef;

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($address, $control, $protocol, $payload) =
      $self->SUPER::unpack('CCn a*', $self->[$__raw])
         or return undef;

   $self->[$__address]  = $address;
   $self->[$__control]  = $control;
   $self->[$__protocol] = $protocol;
   $self->[$__payload]  = $payload;

   $self;
}

sub encapsulate {
   my $types = {
      NP_PPP_PROTOCOL_IPv4()   => 'IPv4',
      NP_PPP_PROTOCOL_DDP()    => 'DDP',
      NP_PPP_PROTOCOL_IPX()    => 'IPX',
      NP_PPP_PROTOCOL_IPv6()   => 'IPv6',
      NP_PPP_PROTOCOL_CDP()    => 'CDP',
      NP_PPP_PROTOCOL_PPPLCP() => 'PPPLCP',
   };

   $types->{shift->[$__protocol]} || $self->[$__nextLayer];
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   sprintf "$l: address:0x%02x  control:0x%02x  protocol:0x%04x",
      $self->[$__address], $self->[$__control], $self->[$__protocol];
}

#
# Helpers
#

sub _isProtocol      { shift->[$__protocol] == shift()            }
sub isProtocolIpv4   { shift->_isProtocol(NP_PPP_PROTOCOL_IPv4)   }
sub isProtocolPpplcp { shift->_isProtocol(NP_PPP_PROTOCOL_PPPLCP) }

1;

__END__

=head1 NAME

Net::Frame::PPP - Point-to-Point Protocol layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:ppp);
   require Net::Packet::PPP;

   # Build a layer
   my $layer = Net::Packet::PPP->new(
      protocol => NP_PPP_PROTOCOL_IPv4,
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::PPP->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the Point-to-Point Protocol layer.

See also B<Net::Packet::Layer> and B<Net::Packet::Layer2> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<protocol> - 16 bits

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

protocol: NP_PPP_PROTOCOL_IPv4

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<isProtocolIpv4>

=item B<isProtocolPpplcp>

Return 1 when encpasulated layer is of respective type. 0 otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:ppp);

=over 4

=item B<NP_PPP_HDR_LEN>

PPP header length.

=item B<NP_PPP_PROTOCOL_IPv4>

=item B<NP_PPP_PROTOCOL_PPPLCP>

Various supported encapsulated layer types.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
