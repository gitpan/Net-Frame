#
# $Id: Makefile.PL 306 2009-05-23 13:34:12Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::Frame',
   VERSION_FROM  => 'lib/Net/Frame.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Socket6       => 0,
      Net::IPv6Addr => 0,
      Bit::Vector   => 0,
   },
);
