use Test::More;
use optimize::subs;

sub foo { "Original" }
sub bar { foo() }

*foo = sub { "Replaced" };

my $ret = bar();

is($ret, "Original");

*foo->();
&{*foo};
*foo{CODE}->();
*{"foo"}->();
&{*{"foo"}};
*{ *foo }->();

sub {...}->(); # remove the refgen, change to a cv variant

done_testing;
