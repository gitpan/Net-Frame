eval "use Test::Pod::Coverage tests => 11";
if ($@) {
   use Test;
   plan(tests => 1);
   skip("Test::Pod::Coverage required for testing");
}
else {
   my $trustparents = { coverage_class => 'Pod::Coverage::CountParents' };

   pod_coverage_ok("Net::Frame::IPv4", $trustparents);
   pod_coverage_ok("Net::Frame::TCP",  $trustparents);
   pod_coverage_ok("Net::Frame::UDP",  $trustparents);
   pod_coverage_ok("Net::Frame::ARP",  $trustparents);
   pod_coverage_ok("Net::Frame::ETH",  $trustparents);
   pod_coverage_ok("Net::Frame::NULL", $trustparents);
   pod_coverage_ok("Net::Frame::PPP",  $trustparents);
   pod_coverage_ok("Net::Frame::RAW",  $trustparents);
   pod_coverage_ok("Net::Frame::SLL",  $trustparents);

   pod_coverage_ok("Net::Frame::Layer");
   pod_coverage_ok("Net::Frame::Utils");
}
