#
# $Id: Layer.pm 357 2014-04-08 13:34:04Z gomor $
#
package Net::Frame::Layer;
use strict;
use warnings;

require Class::Gomor::Array;
require Exporter;
our @ISA = qw(Class::Gomor::Array Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NF_LAYER_NONE
      NF_LAYER_UNKNOWN
      NF_LAYER_NOT_AVAILABLE 
   )],
   subs => [qw(
      getHostIpv4Addr
      getHostIpv4Addrs
      getHostIpv6Addr
      inetAton
      inetNtoa
      inet6Aton
      inet6Ntoa
      getRandomHighPort
      getRandom32bitsInt
      getRandom16bitsInt
      convertMac
      inetChecksum
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
   @{$EXPORT_TAGS{subs}},
);

use constant NF_LAYER_NONE          => 0;
use constant NF_LAYER_UNKNOWN       => 1;
use constant NF_LAYER_NOT_AVAILABLE => 2;

our @AS = qw(
   raw
   payload
   nextLayer
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

use Carp;

sub new { shift->SUPER::new(nextLayer => NF_LAYER_NONE, @_) }

sub layer {
   my $layer = ref(shift);
   $layer =~ s/^Net::Frame::Layer:://;
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

sub encapsulate      { shift->nextLayer              }
sub computeLengths   { 1                             }
sub computeChecksums { 1                             }
sub print            { $self->layer.': to implement' }
sub getLength        { 0                             }

sub dump { CORE::unpack('H*', shift->raw) }

#
# Useful subroutines
#

# load AF_INET and default imports from Socket.  Safe back to at least 5.8.8
use Socket qw(:DEFAULT AF_INET);
BEGIN {
    # imports that may or may not be in Socket.
    my @imports = (
        qw(AF_INET6 NI_NUMERICHOST NI_NUMERICSERV getaddrinfo getnameinfo));
    my @socket6_imports;

    # This might be overkill, but I'm not certain that all these imports
    # were added to Socket at the same time.
    for my $export (@imports) {
        eval { Socket->import($export); };
        if ($@) {
            push @socket6_imports, $export;
        }
    }

    eval {
        # Test to see if the sub works.
        # Socket::inet_ntop() may exist, but die with:
        # Socket::inet_ntop not implemented on this architecture
        Socket::inet_ntop( AF_INET, "\0\0\0\0" );    # test
        Socket->import('inet_ntop');    # import if the test doesn't die
    };
    if ($@) {
        push @socket6_imports, 'inet_ntop';
    }
    eval {
        # Test to see if the sub works.
        # Socket::inet_pton() may exist, but die with:
        # Socket::inet_pton not implemented on this architecture
        Socket::inet_pton( AF_INET, '0.0.0.0' );    # test
        Socket->import('inet_pton');    # import if the test doesn't die
    };
    if ($@) {
        push @socket6_imports, 'inet_pton';
    }

    if (@socket6_imports) {

        # something we want wasn't found in Socket time to try Socket6
        eval { require Socket6 };
        die $@ if $@;
        Socket6->import(@socket6_imports);
    }
}

require Net::IPv6Addr;

sub getHostIpv4Addr {
   my ($name) = @_;

   return undef unless $name;
   return $name if $name =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

   my @addrs = (gethostbyname($name))[4];
   @addrs ? return join('.', CORE::unpack('C4', $addrs[0]))
          : carp("@{[(caller(0))[3]]}: unable to resolv `$name' hostname\n");
   return undef;
}

sub getHostIpv4Addrs {
   my ($name) = @_;

   return undef unless $name;
   return $name if $name =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

   my @addrs = (gethostbyname($name))[4];
   @addrs ? return @addrs
          : carp("@{[(caller(0))[3]]}: unable to resolv `$name' hostname\n");
   return ();
}

sub getHostIpv6Addr {
   my ($name) = @_;

   return undef unless $name;
   return $name if Net::IPv6Addr::is_ipv6($name);

   my @res = getaddrinfo($name, 'ssh', AF_INET6, SOCK_STREAM);
   if (@res >= 5) {
      my ($ipv6) = getnameinfo($res[3], NI_NUMERICHOST | NI_NUMERICSERV);
      $ipv6 =~ s/%.*$//;
      return $ipv6;
   }
   else {
      carp("@{[(caller(0))[3]]}: unable to resolv `$name' hostname\n");
   }
   undef;
}

sub inetAton  { inet_aton(shift()) }
sub inetNtoa  { inet_ntoa(shift()) }
sub inet6Aton { inet_pton(AF_INET6, shift()) }
sub inet6Ntoa { inet_ntop(AF_INET6, shift()) }

sub getRandomHighPort {
   my $highPort = int rand 0xffff;
   $highPort += 1024 if $highPort < 1025;
   $highPort;
}

sub getRandom32bitsInt { int rand 0xffffffff }
sub getRandom16bitsInt { int rand 0xffff     }

sub convertMac {
   return lc(join(':', $_[0] =~ /../g));
}

sub inetChecksum {
   my ($phpkt) = @_;

   $phpkt      .= "\x00" if length($phpkt) % 2;
   my $len      = length $phpkt;
   my $nshort   = $len / 2;
   my $checksum = 0;
   $checksum   += $_ for CORE::unpack("S$nshort", $phpkt);
   # XXX: This line never does anything as the lenth was made even above. Currently testing it breaks nothing.
   #$checksum   += CORE::unpack('C', substr($phpkt, $len - 1, 1)) if $len % 2;
   $checksum    = ($checksum >> 16) + ($checksum & 0xffff);

   CORE::unpack('n',
      CORE::pack('S', ~(($checksum >> 16) + $checksum) & 0xffff),
   );
}

1;

__END__

=head1 NAME

Net::Frame::Layer - base class for all layer objects

=head1 DESCRIPTION

This is the base class for all other layer modules. It provides those layers with inheritable attributes, methods, constants and useful subroutines.

=head1 ATTRIBUTES

=over 4

=item B<raw>

Stores the raw layer (as captured from the network, or packed to send to network).

=item B<payload>

Stores what is not part of the layer, that is the encapsulated part to be decoded by upper layers.

=item B<nextLayer>

User definable next layer. It may be used to define custom protocols.

=back

=head1 METHODS

=over 4

=item B<new>

=item B<new> (hash)

Object constructor.

=item B<layer>

Returns the string describing the layer (example: 'IPv4' for a B<Net::Frame::Layer::IPv4> object).

=item B<computeLengths>

=item B<computeChecksums>

Generally, when a layer is built, some attributes are not yet known until all layers that will be assembled are known. Those methods computes various lengths and checksums attributes found in a specific layer. Return 1 on success, undef otherwise. The usage depends from layer to layer, so see related documentation.

Also note that in most cases, you will need to call B<computeLength> before B<computeChecksums>, because checksums may depend upon lengths.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns the raw packed string on success, undef otherwise. Result is stored into B<raw> attribute.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns B<$self> on success, undef otherwise.

=item B<encapsulate>

Returns the next layer type (parsed from payload). This is the same string as returned by B<layer> method.

=item B<getLength>

Returns the layer length in bytes.

=item B<getPayloadLength>

Returns the length of layer's payload in bytes.

=item B<print>

Just returns a string in a human readable format describing attributes found in the layer.

=item B<dump>

Just returns a string in hexadecimal format which is how the layer appears on the network.

=back

=head1 USEFUL SUBROUTINES

Load them: use Net::Frame::Layer qw(:subs);

=over 4

=item B<getHostIpv4Addr> (hostname)

Resolves IPv4 address of specified hostname.

=item B<getHostIpv4Addrs> (hostname)

Same as above, but returns an array of IPv4 addresses.

=item B<getHostIpv6Addr> (hostname)

Resolves IPv6 address of specified hostname.

=item B<inet6Aton> (IPv6 address)

Takes IPv6 address and returns the network form.

=item B<inet6Ntoa> (IPv6 network form)

Takes IPv6 address in network format, and returns the IPv6 human form.

=item B<inetAton> (IPv4 address)

=item B<inetNtoa> (IPv4 network form)

Same as for IPv6, but for IPv4 addresses.

=item B<convertMac> (MAC network form)

Takes a MAC address from network form, and returns the human form.

=item B<getRandom16bitsInt>

=item B<getRandom32bitsInt>

Returns respectively a random 16 bits integer, and a random 32 bits integer.

=item B<getRandomHighPort>

Returns a random high port (> 1024).

=item B<inetChecksum> (pseudo header format)

Will take a frame in pseudo header format, and compute the INET checksum.

=back

=head1 CONSTANTS

Load them: use Net::Frame::Layer qw(:consts);

=over 4

=item B<NF_LAYER_NONE>

=item B<NF_LAYER_UNKNOWN>

=item B<NF_LAYER_NOT_AVAILABLE>

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006-2014, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
