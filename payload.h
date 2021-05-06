// SPDX-License-Identifier: GPL-2.0

static inline void payload(void)
{
	struct timeval before, after, diff;
	uint64_t lapsed;
	int i;

	fprintf(stdout, "Calling getpid() %d times\n", N_CALL);

	if (gettimeofday(&before, NULL) < 0)
		exit(1);

	for (i = 0; i < N_CALL; i++)
		syscall(__NR_getpid);

	if (gettimeofday(&after, NULL) < 0)
		exit(1);

	timersub(&after, &before, &diff);
	lapsed = ((uint64_t)diff.tv_sec) * 1000000 + ((uint64_t)diff.tv_usec);

	fprintf(stdout, "Time lapsed: %" PRIu64 " us\n", lapsed);
}
