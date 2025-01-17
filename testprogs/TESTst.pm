use strict;
use warnings FATAL => qw(uninitialized);

# TESTrun helper functions (single-threaded implementation).

my @tests;
my $done;

sub my_tmp_id {
	return 'main';
}

sub set_njobs {
	print "INFO: This Perl does not support threads.\n";
	my $njobs = shift;
	die sprintf "ERROR: Impossible to run $njobs tester threads!" if $njobs > 1;
}

sub start_tests {
	@tests = @_;
	$done = 0;
}

# Here ordering of the results is obviously the same as ordering of the tests.
sub get_next_result {
	return undef if $done == scalar @tests;
	my $result = $tests[$done]{func} ($tests[$done]->%*);
	$result->{label} = $tests[$done]{label};
	$done++;
	return $result;
}

1;
