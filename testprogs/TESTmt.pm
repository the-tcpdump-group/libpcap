use strict;
use warnings FATAL => qw(uninitialized);
use threads;
use Thread::Queue;

# TESTrun helper functions (multithreaded implementation).

my $njobs;
my $tmpid;
my @tests;
my @result_queues;
my @tester_threads;
my $next_to_dequeue;

sub my_tmp_id {
	return $tmpid;
}

sub set_njobs {
	$njobs = shift;
	print "INFO: This Perl supports threads, using $njobs tester thread(s).\n";
}

# Iterate over the list of tests, pick tests that belong to the current job,
# run one test at a time and send the result to the job's results queue.
sub tester_thread_func {
	my $jobid = shift;
	$tmpid = sprintf 'job%03u', $jobid;
	for (my $i = $jobid; $i < scalar @tests; $i += $njobs) {
		my $result = $tests[$i]{func} ($tests[$i]->%*);
		$result->{label} = $tests[$i]{label};
		$result_queues[$jobid]->enqueue ($result);
	}
	# Instead of detaching let the receiver join, this works around File::Temp
	# not cleaning up.
	$result_queues[$jobid]->end;
}

sub start_tests {
	@tests = @_;
	for (0 .. $njobs - 1) {
		$result_queues[$_] = Thread::Queue->new;
		$tester_threads[$_] =  threads->create (\&tester_thread_func, $_);
	}
	$next_to_dequeue = 0;
}

# Here ordering of the results is the same as ordering of the tests because
# this function starts at job 0 and continues round-robin, which reverses the
# interleaving done in the thread function above; also because every attempt
# to dequeue blocks until it returns exactly one result or reaches the end of
# queue.
sub get_next_result {
	for (0 .. $njobs - 1) {
		my $result = $result_queues[$next_to_dequeue]->dequeue;
		$next_to_dequeue = ($next_to_dequeue + 1) % $njobs;
		return $result if defined $result;
	}
	# All queues have ended.
	$_->join foreach @tester_threads;
	return undef;
}

1;
