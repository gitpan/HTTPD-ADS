# -*- perl -*-

# t/005_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'WWW::APS::AbuseNotify' ); }

my $object = WWW::APS::AbuseNotify->new ();
isa_ok ($object, 'WWW::APS::AbuseNotify');


