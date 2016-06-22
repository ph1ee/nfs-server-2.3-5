/*
 * failsafe.c
 *
 * Copyright (C) 1998, <okir@monad.swb.de>
 *
 * Implements fail-safe mode for nfsd/mountd.
 */

#include "system.h"
#include "xmalloc.h"
#include "logging.h"
#include "signals.h"
#include <sys/wait.h>

void
failsafe(int level, int ncopies)
{
	pid_t *servers;
	int running;
	int child;
	int i;
	pid_t pid;
	int signo;
	int status;
	time_t last_restart = 0, now;
	int restarts = 0;
	unsigned int backoff = 60;

	servers = (pid_t *) xmalloc((unsigned int) (ncopies * sizeof(int)));
	memset(servers, 0, ncopies * sizeof(pid_t));

	/* Loop forever, until we get SIGTERM */

	running = 0;

	while (1) {
		while (running < ncopies) {
			if ((now = time(NULL)) == last_restart) {
				if (++restarts > 2 * ncopies) {
					dbg_printf(__FILE__, __LINE__,
						   L_ERROR,
						   "Servers restarting too "
						   "quickly, backing off.");
					if (backoff < (60 * 60)) {
						backoff <<= 1;
					}
					sleep(backoff);
				}
			} else {
				last_restart = now;
				restarts = 0;
				backoff = 60;
			}

			/* Locate a free pid slot */

			for (i = 0, child = -1; i < ncopies; i++) {
				if (servers[i] == 0) {
					child = i;
					break;
				}
			}

			if (child < 0) {
				dbg_printf(__FILE__, __LINE__, L_FATAL,
					   "failsafe: no pid slot?!");
			}

			dbg_printf(__FILE__, __LINE__, D_GENERAL,
				   "starting server thread %d...\n",
				   child + 1);

			pid = fork();

			if (pid < 0) {
				dbg_printf(__FILE__, __LINE__, L_FATAL,
					   "Unable to fork for failsafe: %s",
					   strerror(errno));
			}

			if (pid == 0) {
				/* Child process: continue with execution. */
				return;
			}

			servers[child] = pid;
			running++;
		}

		/* Ignore some signals */

		ignore_signal(SIGTERM);
		ignore_signal(SIGHUP);
		ignore_signal(SIGINT);
		ignore_signal(SIGCHLD);

		if ((pid = wait(&status)) < 0) {
			dbg_printf(__FILE__, __LINE__,
				   (errno == ECHILD) ? L_FATAL : L_WARNING,
				   "failsafe: wait(): %s", strerror(errno));
			continue;
		}

		/* Locate the child */

		for (i = 0, child = -1; i < ncopies; i++) {
			if (servers[i] == pid) {
				child = i;
				break;
			}
		}

		if (child < 0) {
			dbg_printf(__FILE__, __LINE__, L_WARNING,
				   "failsafe: unknown child (pid %d) terminated",
				   pid);
			continue;
		}

		/* Book-keeping */

		servers[child] = 0;
		running--;

		if (WIFSIGNALED(status)) {
			signo = WTERMSIG(status);
			if (signo == SIGTERM) {
				dbg_printf(__FILE__, __LINE__, L_NOTICE,
					   "failsafe: "
					   "child %d terminated by SIGTERM. %s.",
					   pid,
					   running ? "Continue" : "Exit");
			} else {
				dbg_printf(__FILE__, __LINE__, L_WARNING,
					   "failsafe: "
					   "child %d terminated by SIG %s. "
					   "Restarting.", pid, signo);
				child = -1;	/* Restart */
			}
		} else if (WIFEXITED(status)) {
			dbg_printf(__FILE__, __LINE__, L_NOTICE, "failsafe: "
				   "child %d exited, status %d.",
				   pid, WEXITSTATUS(status));
		} else {
			dbg_printf(__FILE__, __LINE__, L_ERROR, "failsafe: "
				   "abnormal child termination, "
				   "pid=%d status=%d. Restarting.",
				   pid, status);
			child = -1;	/* Restart */
		}

		/* If child >= 0, we should not restart */

		if (child >= 0) {
			if (!running) {
				dbg_printf(__FILE__, __LINE__, D_GENERAL,
					   "No more children, exiting.");
				exit(0);
			}
			for (i = child; i < ncopies - 1; i++) {
				servers[i] = servers[i + 1];
			}
			ncopies--;	/* Make sure we start no new servers */
		}
	}
}

/*
 * Failsafe session, catch core file.
 *
 * Not yet implemented.
 * General outline: we need to fork first, because nfsd changes
 * uids frequently, and the kernel won't write out a core file after
 * that. The forked proc starts out with a clean dumpable flag though.
 *
 * After the fork, we might want to make sure we end up in some common
 * directory that the failsafe loop knows about.
 */
void
failsafe_loop(int level, void (*function) (void))
{
	/* NOP */
}
