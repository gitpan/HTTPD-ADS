# -*- perl -*-

# t/004_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'HTTPD::ADS::OpenProxyDetector' ); }

my $object = HTTPD::ADS::OpenProxyDetector->new ();
isa_ok ($object, 'HTTPD::ADS::OpenProxyDetector');


