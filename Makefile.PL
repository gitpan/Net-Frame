#
# $Id: Makefile.PL,v 1.4 2006/12/09 13:25:52 gomor Exp $
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
      Net::Libdnet  => 0,
      Net::IPv6Addr => 0,
      Bit::Vector   => 0,
   },
);
