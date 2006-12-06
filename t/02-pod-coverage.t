eval "use Test::Pod::Coverage tests => 11";
if ($@) {
   use Test;
   plan(tests => 1);
   skip("Test::Pod::Coverage required for testing");
}
else {
   pod_coverage_ok("Net::Frame::IPv4");
   pod_coverage_ok("Net::Frame::TCP");
   pod_coverage_ok("Net::Frame::UDP");
   pod_coverage_ok("Net::Frame::ARP");
   pod_coverage_ok("Net::Frame::ETH");
   pod_coverage_ok("Net::Frame::NULL");
   pod_coverage_ok("Net::Frame::PPP");
   pod_coverage_ok("Net::Frame::RAW");
   pod_coverage_ok("Net::Frame::SLL");
   pod_coverage_ok("Net::Frame::Layer");
   pod_coverage_ok("Net::Frame::Utils");
}
