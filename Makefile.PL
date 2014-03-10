#
# $Id: Makefile.PL 353 2014-03-10 12:25:04Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

my @conditions_modules = ();
eval {
  require Socket;
  Socket->import(
    qw(AF_INET6 NI_NUMERICHOST NI_NUMERICSERV getaddrinfo getnameinfo inet_pton inet_ntop));
};
if ($@) {
  @conditions_modules = ( Socket6 => 0 );
}

WriteMakefile(
   NAME          => 'Net::Frame',
   VERSION_FROM  => 'lib/Net/Frame.pm',
   LICENSE       => 'artistic',
   ABSTRACT_FROM => 'lib/Net/Frame.pm',
   AUTHOR        => 'GomoR <gomor-cpan_at_gomor.org>',
   PREREQ_PM     => {
      Class::Gomor  => '1.00',
      Net::IPv6Addr => 0,
      Bit::Vector   => 0,
      @conditions_modules,
   },
);
