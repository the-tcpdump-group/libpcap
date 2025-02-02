require 5.8.4; # Solaris 10
use strict;
use warnings FATAL => qw(uninitialized);

# TESTrun helper functions (single-threaded implementation).

my @tests;

sub my_tmp_id {
	return 'main';
}

sub set_njobs {
	print "INFO: This Perl does not support threads.\n";
	my $njobs = shift;
	die "ERROR: Impossible to run $njobs tester threads!" if $njobs > 1;
}

sub start_tests {
	@tests = @_;
}

# Here ordering of the results is obviously the same as ordering of the tests.
sub get_next_result {
	my $test = shift @tests;
	return undef unless defined $test;
	my $result = $test->{func} ($test);
	$result->{label} = $test->{label};
	return $result;
}

1;
