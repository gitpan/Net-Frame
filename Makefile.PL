#
# $Id: Makefile.PL,v 1.3 2006/12/06 21:17:04 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::Frame',
   VERSION_FROM  => 'lib/Net/Frame.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Socket6       => 0,
      Net::Libdnet  => 0,
      Net::IPv6Addr => 0,
      Bit::Vector   => 0,
   },
);
