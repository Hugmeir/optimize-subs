#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'optimize::subs' ) || print "Bail out!\n";
}

diag( "Testing optimize::subs $optimize::subs::VERSION, Perl $], $^X" );
