# -*- perl -*-

# t/003_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'HTTPD::ADS::DBI' ); }

my $object = HTTPD::ADS::DBI->new ();
isa_ok ($object, 'HTTPD::ADS::DBI');


