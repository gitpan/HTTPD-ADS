# -*- perl -*-

# t/003_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'WWW::APS::DBI' ); }

my $object = WWW::APS::DBI->new ();
isa_ok ($object, 'WWW::APS::DBI');


