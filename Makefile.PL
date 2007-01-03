#
# $Id: Makefile.PL,v 1.5 2007/01/03 21:39:28 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame',
   VERSION_FROM  => 'lib/Net/Frame.pm',
   LICENSE       => 'Artistic',
   ABSTRACT_FROM => 'lib/Net/Frame.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Socket6       => 0,
      Net::IPv6Addr => 0,
      Bit::Vector   => 0,
   },
);
