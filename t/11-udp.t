use Test;
BEGIN { plan(tests => 1) }

use Net::Frame::UDP qw(:consts);

my $l = Net::Frame::UDP->new;
$l->pack;
$l->unpack;

print $l->print."\n";

my $encap = $l->encapsulate;
$encap ? print "[$encap]\n" : print "[none]\n";

ok(1);
