# -*- perl -*-

# t/004_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'WWW::APS::OpenProxyDetector' ); }

my $object = WWW::APS::OpenProxyDetector->new ();
isa_ok ($object, 'WWW::APS::OpenProxyDetector');


