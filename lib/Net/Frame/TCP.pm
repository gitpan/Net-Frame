#
# $Id: TCP.pm,v 1.4 2006/12/03 16:07:35 gomor Exp $
#
package Net::Frame::TCP;
use strict;
use warnings;

use Net::Frame::Layer qw(:consts);
require Exporter;
our @ISA = qw(Net::Frame::Layer Exporter);

our %EXPORT_TAGS = (
   consts => [qw(
      NP_TCP_HDR_LEN
      NP_TCP_FLAG_FIN
      NP_TCP_FLAG_SYN
      NP_TCP_FLAG_RST
      NP_TCP_FLAG_PSH
      NP_TCP_FLAG_ACK
      NP_TCP_FLAG_URG
      NP_TCP_FLAG_ECE
      NP_TCP_FLAG_CWR
   )],
);
our @EXPORT_OK = (
   @{$EXPORT_TAGS{consts}},
);

use constant NP_TCP_HDR_LEN  => 20;
use constant NP_TCP_FLAG_FIN => 0x01;
use constant NP_TCP_FLAG_SYN => 0x02;
use constant NP_TCP_FLAG_RST => 0x04;
use constant NP_TCP_FLAG_PSH => 0x08;
use constant NP_TCP_FLAG_ACK => 0x10;
use constant NP_TCP_FLAG_URG => 0x20;
use constant NP_TCP_FLAG_ECE => 0x40;
use constant NP_TCP_FLAG_CWR => 0x80;

our @AS = qw(
   src
   dst
   flags
   win
   seq
   ack
   off
   x2
   checksum
   urp
   options
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

no strict 'vars';

use Net::Frame::Utils qw(inetChecksum getRandomHighPort getRandom32bitsInt
   inetAton inet6Aton);

sub new {
   shift->SUPER::new(
      src      => getRandomHighPort(),
      dst      => 0,
      seq      => getRandom32bitsInt(),
      ack      => 0,
      x2       => 0,
      off      => 0,
      flags    => NP_TCP_FLAG_SYN,
      win      => 0xffff,
      checksum => 0,
      urp      => 0,
      options  => '',
      @_,
   );
}

sub pack {
   my $self = shift;

   my $offX2Flags = ($self->[$__off] << 12)|(0x0f00 & ($self->[$__x2] << 8))
      |(0x00ff & $self->[$__flags]);

   $self->[$__raw] = $self->SUPER::pack('nnNNnnnn',
      $self->[$__src],
      $self->[$__dst],
      $self->[$__seq],
      $self->[$__ack],
      $offX2Flags,
      $self->[$__win],
      $self->[$__checksum],
      $self->[$__urp],
   ) or return undef;

   if ($self->[$__options]) {
      $self->[$__raw] =
         $self->[$__raw].$self->SUPER::pack('a*', $self->[$__options])
            or return undef;
   }

   if ($self->[$__payload]) {
      $self->[$__raw] =
         $self->[$__raw].$self->SUPER::pack('a*', $self->[$__payload])
            or return undef;
   }

   $self->[$__raw];
}

sub unpack {
   my $self = shift;

   my ($src, $dst, $seq, $ack, $offX2Flags, $win, $checksum, $urp, $payload) =
      $self->SUPER::unpack('nnNNnnnn a*', $self->[$__raw])
         or return undef;

   $self->[$__src]      = $src;
   $self->[$__dst]      = $dst;
   $self->[$__seq]      = $seq;
   $self->[$__ack]      = $ack;
   $self->[$__off]      = ($offX2Flags & 0xf000) >> 12;
   $self->[$__x2]       = ($offX2Flags & 0x0f00) >> 8;
   $self->[$__flags]    = $offX2Flags & 0x00ff;
   $self->[$__win]      = $win;
   $self->[$__checksum] = $checksum;
   $self->[$__urp]      = $urp;
   $self->[$__payload]  = $payload;

   my ($options, $payload2) = $self->SUPER::unpack(
      'a'. $self->getOptionsLength. 'a*', $self->[$__payload]
   ) or return undef;

   $self->[$__options] = $options;
   $self->[$__payload] = $payload2;

   $self;
}

sub getLength { my $self = shift; $self->[$__off] ? $self->[$__off] * 4 : 0 }

sub getOptionsLength {
   my $self = shift;
   my $gLen = $self->getLength;
   my $hLen = NP_TCP_HDR_LEN;
   $gLen > $hLen ? $gLen - $hLen : 0;
}

sub getPayloadLength { shift->SUPER::getPayloadLength }

sub computeLengths {
   my $self = shift;

   my $optLen = ($self->[$__options] && length($self->[$__options])) || 0;

   my $hLen = NP_TCP_HDR_LEN + $self->getOptionsLength;
   $self->[$__off] = ($hLen + $optLen) / 4;
}

sub computeChecksums {
   my $self = shift;
   my ($h)  = @_;

   my $payloadLength = $self->getLength + $self->getPayloadLength;

   my $phpkt;
   if ($h->{type} eq 'IPv4') {
      $phpkt = $self->SUPER::pack('a4a4CCn',
         inetAton($h->{src}), inetAton($h->{dst}), 0, 6, $payloadLength,
      );
   }
   elsif ($type eq 'IPv6') {
      $phpkt = $self->SUPER::pack('a*a*NnCC',
         inet6Aton($h->{src}), inet6Aton($h->{dst}), $payloadLength, 0, 0, 6,
      );
   }

   my $offX2Flags = ($self->[$__off] << 12) | (0x0f00 & ($self->[$__x2] << 8))
                  | (0x00ff & $self->[$__flags]);

   $phpkt .= $self->SUPER::pack('nnNNnnnn',
      $self->[$__src], $self->[$__dst], $self->[$__seq], $self->[$__ack],
      $offX2Flags, $self->[$__win], 0, $self->[$__urp],
   ) or return undef;

   if ($self->[$__options]) {
      $phpkt .= $self->SUPER::pack('a*', $self->[$__options])
         or return undef;
   }

   if ($self->[$__payload]) {
      $phpkt .= $self->SUPER::pack('a*', $self->[$__payload])
         or return undef;
   }

   $self->[$__checksum] = inetChecksum($phpkt);

   1;
}

sub encapsulate { NP_LAYER_NONE }

sub match {
   my $self = shift;
   my ($with) = @_;
      ($with->[$__ack] == $self->[$__seq] + 1)
   || ($with->[$__flags] & NP_TCP_FLAG_RST);
}

sub getKey {
   my $self = shift;
   $self->layer.':'.$self->[$__src].'-'.$self->[$__dst];
}

sub getKeyReverse {
   my $self = shift;
   $self->layer.':'.$self->[$__dst].'-'.$self->[$__src];
}

sub print {
   my $self = shift;

   my $l = $self->layer;
   my $buf = sprintf
      "$l: src:%d  dst:%d  seq:0x%04x  ack:0x%04x \n".
      "$l: off:0x%02x  x2:0x%01x  flags:0x%02x  win:%d  checksum:0x%04x  ".
      "urp:0x%02x",
         $self->[$__src], $self->[$__dst], $self->[$__seq], $self->[$__ack],
         $self->[$__off], $self->[$__x2], $self->[$__flags], $self->[$__win],
         $self->[$__checksum], $self->[$__urp];

   if ($self->[$__options]) {
      $buf .= sprintf("\n$l: optionsLength:%d  options:%s",
         $self->getOptionsLength,
         $self->SUPER::unpack('H*', $self->[$__options])
      ) or return undef;
   }

   $buf;
}

#
# Helpers
#

sub _haveFlag   { (shift->[$__flags] & shift) ? 1 : 0 }
sub haveFlagFin { shift->_haveFlag(NP_TCP_FLAG_FIN)   }
sub haveFlagSyn { shift->_haveFlag(NP_TCP_FLAG_SYN)   }
sub haveFlagRst { shift->_haveFlag(NP_TCP_FLAG_RST)   }
sub haveFlagPsh { shift->_haveFlag(NP_TCP_FLAG_PSH)   }
sub haveFlagAck { shift->_haveFlag(NP_TCP_FLAG_ACK)   }
sub haveFlagUrg { shift->_haveFlag(NP_TCP_FLAG_URG)   }
sub haveFlagEce { shift->_haveFlag(NP_TCP_FLAG_ECE)   }
sub haveFlagCwr { shift->_haveFlag(NP_TCP_FLAG_CWR)   }

1;

__END__

=head1 NAME

Net::Frame::TCP - Transmission Control Protocol layer object

=head1 SYNOPSIS

   use Net::Packet::Consts qw(:tcp);
   require Net::Packet::TCP;

   # Build a layer
   my $layer = Net::Packet::TCP->new(
      dst     => 22,
      options => "\x02\x04\x05\xb4", # MSS=1460
   );
   $layer->pack;

   print 'RAW: '.unpack('H*', $layer->raw)."\n";

   # Read a raw layer
   my $layer = Net::Packet::TCP->new(raw => $raw);

   print $layer->print."\n";
   print 'PAYLOAD: '.unpack('H*', $layer->payload)."\n"
      if $layer->payload;

=head1 DESCRIPTION

This modules implements the encoding and decoding of the TCP layer.

RFC: ftp://ftp.rfc-editor.org/in-notes/rfc793.txt
      
See also B<Net::Packet::Layer> and B<Net::Packet::Layer4> for other attributes and methods.

=head1 ATTRIBUTES

=over 4

=item B<src>

=item B<dst>

Source and destination ports.

=item B<flags>

TCP flags, see CONSTANTS.

=item B<win>

The window size.

=item B<seq>

=item B<ack>

Sequence and acknowledgment numbers.

=item B<off>

The size in number of words of the TCP header.

=item B<x2>

Reserved field.

=item B<checksum>

The TCP header checksum.

=item B<urp>

Urgent pointer.

=item B<options>

TCP options, as a hexadecimal string.

=back

=head1 METHODS

=over 4

=item B<new>

Object constructor. You can pass attributes that will overwrite default ones. Default values:

src:      getRandomHighPort()

dst:      0

seq:      getRandom32bitsInt()

ack:      0

x2:       0

off:      0

flags:    NP_TCP_FLAG_SYN

win:      0xffff

checksum: 0

urp:      0

options:  ""

=item B<recv>

Will search for a matching replies in B<framesSorted> or B<frames> from a B<Net::Packet::Dump> object.

=item B<pack>

Packs all attributes into a raw format, in order to inject to network. Returns 1 on success, undef otherwise.

=item B<unpack>

Unpacks raw data from network and stores attributes into the object. Returns 1 on success, undef otherwise.

=item B<getHeaderLength>

Returns the header length in bytes, not including TCP options.

=item B<getOptionsLength>

Returns options length in bytes.

=item B<haveFlagFin>

=item B<haveFlagSyn>

=item B<haveFlagRst>

=item B<haveFlagPsh>

=item B<haveFlagAck>

=item B<haveFlagUrg>

=item B<haveFlagEce>

=item B<haveFlagCwr>

Returns 1 if the specified TCP flag is set in B<flags> attribute, 0 otherwise.

=back

=head1 CONSTANTS

Load them: use Net::Packet::Consts qw(:tcp);

=over 4

=item B<NP_TCP_FLAG_FIN>

=item B<NP_TCP_FLAG_SYN>

=item B<NP_TCP_FLAG_RST>

=item B<NP_TCP_FLAG_PSH>

=item B<NP_TCP_FLAG_ACK>

=item B<NP_TCP_FLAG_URG>

=item B<NP_TCP_FLAG_ECE>

=item B<NP_TCP_FLAG_CWR>

TCP flag constants.

=back

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
