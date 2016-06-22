
/*
 * mountd	This program handles RPC "NFS" mount requests.
 *
 * Usage:	[rpc.]mountd [-dhnpv] [-f authfile]
 *
 * Authors:	Mark A. Shand, May 1988
 *		Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include "system.h"
#include <getopt.h>
#include "mountd.h"
#include "rpcmisc.h"
#include "rmtab.h"
#include "haccess.h"
#include "failsafe.h"
#include "signals.h"
#include <rpc/pmap_clnt.h>
#include "xrealpath.h"

#ifdef S_SPLINT_S
# ifndef _PC_LINK_MAX
#  define _PC_LINK_MAX 0
# endif /* ! _PC_LINK_MAX */
#endif /* S_SPLINT_S */

#define ENABLE_LOG_MOUNTS 1

#ifdef ENABLE_LOG_MOUNTS
static void
log_mount(char *type, char *action, char *path, struct svc_req *rqstp)
{
	dbg_printf(__FILE__, __LINE__, L_NOTICE,
		   "NFS %s request %s (%s, from %s)\n",
		   type, action, path,
		   inet_ntoa(svc_getcaller(rqstp->rq_xprt)->sin_addr));
}
#else
#define log_mount(type, action, path, rqstp)
#endif /* ENABLE_LOG_MOUNTS */

static void usage(FILE *, int);
static void terminate(void);
static RETSIGTYPE sigterm(int sig);

/*
 * Option table for mountd
 */
static struct option longopts[] = {
	{"debug", required_argument, 0, 'd'},
	{"exports-file", required_argument, 0, 'f'},
	{"help", 0, 0, 'h'},
	{"allow-non-root", 0, 0, 'n'},
	{"port", required_argument, 0, 'P'},
	{"promiscous", 0, 0, 'p'},
	{"re-export", 0, 0, 'r'},
	{"no-spoof-trace", 0, 0, 't'},
	{"version", 0, 0, 'v'},
	{"fail-safe", optional_argument, 0, 'z'},
	{NULL, 0, 0, 0}
};

static const char *shortopts = "Fd:f:hnpP:rtvz::";

/*
 * Table of supported versions
 */
static unsigned long mountd_versions[] = {
	MOUNTVERS,
	MOUNTVERS_POSIX,
	0
};

char argbuf[MNTPATHLEN + 1];
char *auth_file = NULL;
static char *program_name;
int need_reinit = 0;

int
main(int argc, char **argv)
{
	int foreground = 0;
	int failsafe_level = 0;
	int req_port = 0;
	in_port_t port = 0;
	int c;

	program_name = argv[0];
	opterr = 0;

	/* Parse the command line options and arguments. */
	while ((c =
		getopt_long(argc, argv, shortopts, longopts, NULL)) != EOF) {
		switch (c) {
		case 'F':
			foreground = 1;
			break;
		case 'h':
			usage(stdout, 0);
			break;
		case 'd':
			log_enable(optarg);
			break;
		case 'f':
			auth_file = optarg;
			break;
		case 'n':
			allow_non_root = 1;
			break;
		case 'P':
			req_port = atoi(optarg);
			if (req_port <= 0 || req_port > 65535) {
				fprintf(stderr,
					"mountd: bad port number: %s\n",
					optarg);
				usage(stderr, 1);
			}
			port = (in_port_t) req_port;
			break;
		case 'p':
			promiscuous = 1;
			break;
		case 'r':
			re_export = 1;
			break;
		case 't':
			trace_spoof = 0;
			break;
		case 'v':
			printf("Universal NFS Server\n%s %s\n", program_name,
			       PACKAGE_VERSION);
			exit(0);
		case 'z':
			if (optarg) {
				failsafe_level = atoi(optarg);
			} else {
				failsafe_level = 1;
			}
			break;
		case 0:
			break;
		case '?':
			/* fallthrough */
		default:
			usage(stderr, 1);
		}
	}

	/* No more arguments allowed. */
	if (optind != argc) {
		usage(stderr, 1);
	}

	/* Get the default mount port */
	if (!port) {
		struct servent *sp;

		if (!(sp = getservbyname("mount", "udp"))) {
			port = MOUNT_PORT;
		} else {
			port = ntohs((in_port_t) sp->s_port);
		}
	}

	/* Initialize logging. */
	log_open("mountd", foreground);

	/* Create services and register with portmapper */
	rpc_init("mountd", MOUNTPROG, mountd_versions, mount_dispatch, port,
		 0);

	if (!foreground && !_rpcpmstart) {
#ifndef RPC_SVC_FG
		pid_t child;
		/* We first fork off a child. */
		if ((child = fork()) > 0)
			exit(0);
		if (child < 0) {
			dbg_printf(__FILE__, __LINE__, L_FATAL,
				   "mountd: cannot fork: %s\n",
				   strerror(errno));
		}
		/* No more logging to stderr */
		log_set_background();

		/* Now we remove ourselves from the foreground. */
		(void) close(0);
		(void) close(1);
		(void) close(2);

#ifdef HAVE_SETSID
		(void) setsid();
#else
		{
			int fd;

			if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
				ioctl(fd, TIOCNOTTY, (char *) NULL);
				close(fd);
			}
		}
#endif /* HAVE_SETSID */

#endif /* not RPC_SVC_FG */
	}

	/* Initialize the FH module. */
	fh_init();

	/* Initialize the AUTH module. */
	auth_init(auth_file);

	/* Failsafe mode */
	if (failsafe_level) {
		failsafe(failsafe_level, 1);
	}

	/* Enable the LOG toggle with a signal. */
	install_signal_handler(SIGUSR1, log_toggle);

	/* Enable rereading of exports file */
	install_signal_handler(SIGHUP, reinitialize);

	/* Graceful shutdown */
	install_signal_handler(SIGTERM, sigterm);

	atexit(terminate);

	svc_run();

	dbg_printf(__FILE__, __LINE__, L_ERROR, "svc_run() returned\n");

	exit(1);
}

static void
usage(FILE * fp, int n)
{
	fprintf(fp,
		"Usage: %s [-Fhnpv] [-d kind] [-f exports-file] [-P port]\n",
		program_name);
	fprintf(fp, "       [--debug kind] [--help] [--allow-non-root]\n");
	fprintf(fp, "       [--promiscuous] [--version] [--port portnum]\n");
	fprintf(fp, "       [--exports-file=file]\n");
	exit(n);
}

static RETSIGTYPE
sigterm(int sig)
{
	terminate();
	exit(1);
}

static void
terminate(void)
{
	rpc_exit(MOUNTPROG, mountd_versions);
}

RETSIGTYPE
reinitialize(int sig)
{
	static volatile int inprogress = 0;

	if (_rpcsvcdirty) {
		need_reinit = 1;
		return;
	}

	if (inprogress++) {
		return;
	}

	fh_flush(1);
	auth_init(NULL);

	inprogress = 0;
	need_reinit = 0;

	/* Flush the hosts_access table */
	client_flushaccess();
}

/*
 * NULL
 * Do nothing
 */
void *
mountproc_null_1(void *argp, struct svc_req *rqstp)
{
	return ((void *) &result);
}

/*
 * MOUNT
 * This is what the whole protocol is all about
 */
fhstatus *
mountproc_mnt_1(dirpath * argp, struct svc_req *rqstp)
{
	fhstatus *res;
	struct stat stbuf;
	nfs_client *cp;
	nfs_mount *mp;
	char nargbuf[MNTPATHLEN + 1];
	int saved_errno = 0;

	res = (struct fhstatus *) &result;

	if (**argp == '\0') {
		strcpy(argbuf, "/");
	} else {
		/* don't trust librpc */
		strncpy(argbuf, *argp, MNTPATHLEN);
		argbuf[MNTPATHLEN] = '\0';
	}

	/* It is important to resolve symlinks before checking permissions. */
	if (xrealpath(argbuf, nargbuf) == NULL) {
		saved_errno = errno;
	} else {
		strcpy(argbuf, nargbuf);
	}

	log_mount("mount", "received", argbuf, rqstp);

	/* Now authenticate the intruder... */
	if (((cp = auth_clnt(rqstp)) == NULL)
	    || (mp = auth_path(cp, rqstp, argbuf)) == NULL || mp->o.noaccess) {
		res->fhs_status = NFSERR_ACCES;
		log_mount("mount", "blocked", argbuf, rqstp);
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "\tmount status = %d\n", res->fhs_status);
		return (res);
	}

	/* Check the file. We can now return valid results to the client. */
	if ((errno = saved_errno) != 0 || stat(argbuf, &stbuf) < 0) {
		res->fhs_status = nfs_errno();
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "\tmount status = %d\n", res->fhs_status);
		return (res);
	}

	if (!S_ISDIR(stbuf.st_mode) && !S_ISREG(stbuf.st_mode)) {
		res->fhs_status = NFSERR_NOTDIR;
	} else if (!re_export && nfsmounted(argbuf, &stbuf)) {
		res->fhs_status = NFSERR_ACCES;
	} else {
		int status = 
			fh_create((nfs_fh *) & (res->fhstatus_u.fhs_fhandle),
				  argbuf);
		if (status >= 0) {
			res->fhs_status = (unsigned int) status;
		} else {
			res->fhs_status = UINT_MAX; 
		}
		rmtab_add_client(argbuf, rqstp);
		log_mount("mount", "completed", argbuf, rqstp);
	}

	dbg_printf(__FILE__, __LINE__, D_CALL, "\tmount status = %d\n",
		   res->fhs_status);
	return (res);
}

/*
 * DUMP
 * Dump the contents of rmtab on the caller.
 */
mountlist *
mountproc_dump_1(void *argp, struct svc_req * rqstp)
{
	return (rmtab_lst_client());
}

/*
 * UMNT
 * Remove a mounted fs's rmtab entry.
 */
void *
mountproc_umnt_1(dirpath * argp, struct svc_req *rqstp)
{
	rmtab_del_client(*argp, rqstp);
	return ((void *) &result);
}

/*
 * UMNTALL
 * Remove a client's rmtab entry.
 */
void *
mountproc_umntall_1(void *argp, struct svc_req *rqstp)
{
	rmtab_mdel_client(rqstp);
	return ((void *) &result);
}

/*
 * EXPORT
 * Return list of all exported file systems.
 */
exports *
mountproc_export_1(void *argp, struct svc_req *rqstp)
{
	return (&export_list);
}

/*
 * EXPORTALL
 * Same as EXPORT
 */
exports *
mountproc_exportall_1(void *argp, struct svc_req * rqstp)
{
	return (&export_list);
}

/*
 * PATHCONF
 * Since the protocol doesn't include a status field, Sun apparently
 * considers it good practice to let anyone snoop on your system, even if
 * it's pretty harmless data such as pathconf. We don't.
 *
 * Besides, many of the pathconf values don't make much sense on NFS volumes.
 * FIFOs and tty device files represent devices on the *client*, so there's
 * no point in getting the *server's* buffer sizes etc. Wonder what made the
 * Sun people choose these.
 */
pathcnf *
mountproc_pathconf_2(dirpath * argp, struct svc_req * rqstp)
{
	pathcnf *res = (pathcnf *) & result;
	struct stat stbuf;
	nfs_client *cp;
	nfs_mount *mp;
	char nargbuf[MNTPATHLEN + 1];
	char *dir;

	memset(res, 0, sizeof(*res));

	if (**argp == '\0') {
		strcpy(argbuf, "/");
	} else {
		/* don't trust librpc */
		strncpy(argbuf, *argp, MNTPATHLEN);
		argbuf[MNTPATHLEN] = '\0';
	}

	/* It is important to resolve symlinks before checking permissions. */
	if (xrealpath(argbuf, nargbuf) == NULL) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "\trealpath failure in pathconf\n");
		return (res);
	}

	strcpy(argbuf, nargbuf);
	dir = argbuf;

	log_mount("pathconf", "received", dir, rqstp);

	if (stat(dir, &stbuf) < 0) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "\tstat failure in pathconf\n");
		return (res);
	}

	/* Now authenticate the intruder... */
	if (((cp = auth_clnt(rqstp)) == NULL)
	    || (mp = auth_path(cp, rqstp, dir)) == NULL || mp->o.noaccess) {

		log_mount("pathconf", "refused", dir, rqstp);

	} else if (!re_export && nfsmounted(dir, &stbuf)) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "\tnfsmounted failure in pathconf\n");
	} else {
		/* You get what you ask for */

		/* TODO: spec for pathconf says that on success...
		 * "The  limit  is  returned, if one exists. If the system
		 * does not have a limit for  the  requested  resource,  -1
		 * is  returned, and  errno  is unchanged. If there is an
		 * error, -1 is returned, and errno is set to reflect the
		 * nature of the error."  Here, we're not really handling
		 * the case where pathconf returns an error.
		 */

		res->pc_link_max = pathconf(dir, _PC_LINK_MAX);
		res->pc_max_canon = pathconf(dir, _PC_MAX_CANON);
		res->pc_max_input = pathconf(dir, _PC_MAX_INPUT);
		res->pc_name_max = pathconf(dir, _PC_NAME_MAX);
		res->pc_path_max = pathconf(dir, _PC_PATH_MAX);
		res->pc_pipe_buf = pathconf(dir, _PC_PIPE_BUF);
		res->pc_vdisable = (unsigned char) pathconf(dir, _PC_VDISABLE);

		/* Can't figure out what to do with pc_mask */
		res->pc_mask[0] = 0;
		res->pc_mask[1] = 0;

		log_mount("pathconf", "completed", dir, rqstp);

		dbg_printf(__FILE__, __LINE__, D_CALL, "\tpathconf OK\n");
	}
	return (res);
}

/*
 * Don't look. This is an awful hack to overcome a link problem with
 * auth_clnt temporarily.
 */
uid_t
luid(uid_t uid, nfs_mount * mp, struct svc_req * rqstp)
{
	return -2;
}

gid_t
lgid(gid_t gid, nfs_mount * mp, struct svc_req * rqstp)
{
	return -2;
}

void
ugid_free_map(struct ugid_map *map)
{
	/* NOP */
}

void
ugid_map_uid(nfs_mount * mp, uid_t from, uid_t to)
{
	/* NOP */
}

void
ugid_map_gid(nfs_mount * mp, gid_t from, gid_t to)
{
	/* NOP */
}

void
ugid_squash_uids(nfs_mount * mp, uid_t from, uid_t to)
{
	/* NOP */
}

void
ugid_squash_gids(nfs_mount * mp, gid_t from, gid_t to)
{
	/* NOP */
}
