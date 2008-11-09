#
# $Id: Makefile.PL 301 2008-11-09 21:52:06Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame',
   VERSION_FROM  => 'lib/Net/Frame.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame.pm',
   AUTHOR        => 'GomoR <perl@gomor.org>',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Socket6       => 0,
      Net::IPv6Addr => 0,
      Bit::Vector   => 0,
   },
);
