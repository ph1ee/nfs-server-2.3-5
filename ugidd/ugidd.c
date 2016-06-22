
/* UNFSD - copyright Mark A Shand, May 1988.
 *
 * This software maybe be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 *
 * Authors:	Mark A. Shand
 *			Olaf Kirch <okir@monad.swb.de>
 */

#include "system.h"
#include <rpc/pmap_clnt.h>
#include <getopt.h>
#include "logging.h"
#include "haccess.h"
#include "ugid_xdr.c"

#ifndef HAVE_RPCGEN_C
#define authenticate_1_svc	authenticate_1
#define name_uid_1_svc		name_uid_1
#define group_gid_1_svc		group_gid_1
#define uid_name_1_svc		uid_name_1
#define gid_group_1_svc		gid_group_1
#endif

static void ugidprog_1(struct svc_req *rqstp, SVCXPRT * transp);
static void usage(void);

static struct option longopts[] = {
	{"debug", 0, 0, 'd'},
	{NULL, 0, 0, 0}
};

int
main(int argc, char **argv)
{
	SVCXPRT *transp;
	int c;
	int longind;
	int foreground = 0;

#ifndef ENABLE_HOSTS_ACCESS
	fprintf(stderr,
		"\n *** WARNING: This copy of ugidd has been compiled without\n"
		" *** support for host_access checking. This is very risky.\n"
		" *** Please consider recompiling it with access checking.\n");
	sleep(1);
#endif

	while ((c = getopt_long(argc, argv, "d", longopts, &longind)) != EOF) {
		switch (c) {
		case 'd':
			foreground = 1;
			log_enable("ugid");
			break;
		default:
			usage();
		}
	}

	pmap_unset(UGIDPROG, UGIDVERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		(void) fprintf(stderr, "cannot create udp service.\n");
		exit(1);
	}

	if (!svc_register
	    (transp, UGIDPROG, UGIDVERS, ugidprog_1, IPPROTO_UDP)) {
		fprintf(stderr,
			"unable to register (UGIDPROG, UGIDVERS, UDP)\n");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf(stderr, "cannot create tcp service.\n");
		exit(1);
	}

	if (!svc_register
	    (transp, UGIDPROG, UGIDVERS, ugidprog_1, IPPROTO_TCP)) {
		fprintf(stderr,
			"unable to register (UGIDPROG, UGIDVERS, TCP)\n");
		exit(1);
	}

	if (!foreground) {
		pid_t child;
		if ((child = fork()) > 0) {
			exit(0);
		}

		if (child < 0) {
			fprintf(stderr, "ugidd: cannot fork: %s\n",
				strerror(errno));
			exit(-1);
		}

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
	}

	log_open("ugidd", foreground);

	svc_run();

	dbg_printf(__FILE__, __LINE__, L_ERROR, "svc_run() returned\n");

	return 1;
}

static void
usage()
{
	fprintf(stderr, "rpc.ugidd: [-d]\n");
	exit(2);
}

static void
ugidprog_1(struct svc_req *rqstp, SVCXPRT * transp)
{
	union {
		int authenticate_1_arg;
		ugname name_uid_1_arg;
		ugname group_gid_1_arg;
		int uid_name_1_arg;
		int gid_group_1_arg;
	} argument;

	char *result;
	xdrproc_t xdr_argument;
	xdrproc_t xdr_result;
	char *(*local) ();

	if (!client_checkaccess("rpc.ugidd", svc_getcaller(transp), 1)) {
		return;
	}

	switch (rqstp->rq_proc) {
	case NULLPROC:
		svc_sendreply(transp, (xdrproc_t) xdr_void, (char *) NULL);
		return;

	case AUTHENTICATE:
		xdr_argument = (xdrproc_t) xdr_int;
		xdr_result = (xdrproc_t) xdr_int;
		local = (char *(*)()) authenticate_1_svc;
		break;

	case NAME_UID:
		xdr_argument = (xdrproc_t) xdr_ugname;
		xdr_result = (xdrproc_t) xdr_int;
		local = (char *(*)()) name_uid_1_svc;
		break;

	case GROUP_GID:
		xdr_argument = (xdrproc_t) xdr_ugname;
		xdr_result = (xdrproc_t) xdr_int;
		local = (char *(*)()) group_gid_1_svc;
		break;

	case UID_NAME:
		xdr_argument = (xdrproc_t) xdr_int;
		xdr_result = (xdrproc_t) xdr_ugname;
		local = (char *(*)()) uid_name_1_svc;
		break;

	case GID_GROUP:
		xdr_argument = (xdrproc_t) xdr_int;
		xdr_result = (xdrproc_t) xdr_ugname;
		local = (char *(*)()) gid_group_1_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}

	memset(&argument, 0, sizeof(argument));

	if (!svc_getargs(transp, xdr_argument, &argument)) {
		svcerr_decode(transp);
		return;
	}

	result = (*local) (&argument, rqstp);

	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}

	if (!svc_freeargs(transp, xdr_argument, &argument)) {
		fprintf(stderr, "unable to free arguments\n");
		exit(1);
	}
}

int *
authenticate_1_svc(int *argp, struct svc_req *rqstp)
{
	static int res;
	int s = 0;
	struct sockaddr_in sendaddr;
	struct sockaddr_in destaddr;
	int dummy;
	short lport;

	if ((*argp < 0) || (*argp > 65535)) {
		goto bad;
	}

	memset(&res, 0, sizeof(res));
	destaddr = *svc_getcaller(rqstp->rq_xprt);
	destaddr.sin_port = htons((in_port_t) *argp);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		goto bad;
	}

	setsockopt(s, SOL_SOCKET, SO_LINGER, 0, 0);
	memset(&sendaddr, 0, sizeof(sendaddr));

	/* find a reserved port */
	lport = IPPORT_RESERVED - 1;
	sendaddr.sin_family = (sa_family_t) AF_INET;
	sendaddr.sin_addr.s_addr = INADDR_ANY;

	for (;;) {
		sendaddr.sin_port = htons((u_short) lport);

		if (bind(s, (struct sockaddr *) &sendaddr, (int) sizeof(sendaddr)) >=
		    0) {
			break;
		}

		if (errno != EADDRINUSE && EADDRNOTAVAIL) {
			goto bad;
		}

		lport--;

		if (lport <= IPPORT_RESERVED / 2) {
			/* give up */
			break;
		}
	}

	if (sendto(s, &dummy, sizeof dummy, 0,
		   (struct sockaddr *) &destaddr, (int) sizeof(destaddr)) < 0) {
		goto bad;
	}

	close(s);
	res = 0;
	return (&res);

      bad:
	close(s);
	res = errno == 0 ? -1 : errno;
	return (&res);
}

int *
name_uid_1_svc(ugname * argp, struct svc_req *rqstp)
{
	static int res;
	struct passwd *pw;

	memset(&res, 0, sizeof(res));

	if ((pw = getpwnam(*argp)) == NULL) {
		res = NOBODY;
	} else {
		res = (int) pw->pw_uid;
	}

	return (&res);
}

int *
group_gid_1_svc(ugname * argp, struct svc_req *rqstp)
{
	static int res;
	struct group *gr;

	memset(&res, 0, sizeof(res));

	if ((gr = getgrnam(*argp)) == NULL) {
		res = NOBODY;
	} else {
		res = (int) gr->gr_gid;
	}

	return (&res);
}

ugname *
uid_name_1_svc(int *argp, struct svc_req * rqstp)
{
	static ugname res;
	struct passwd *pw;

	memset(&res, 0, sizeof(res));

        if ((*argp < 0) || (*argp > (int) ((gid_t) -1))) {   
                res = ""; 
                return (&res);
        } 

	if ((pw = getpwuid((uid_t) *argp)) == NULL) {
		res = "";
	} else {
		res = pw->pw_name;
	}

	return (&res);
}

ugname *
gid_group_1_svc(int *argp, struct svc_req * rqstp)
{
	static ugname res;
	struct group *gr;

	memset(&res, 0, sizeof(res));

	if ((*argp < 0) || (*argp > (int) ((gid_t) -1))) {
		res = "";
		return (&res);
	}

	if ((gr = getgrgid((gid_t) *argp)) == NULL) {
		res = "";
	} else {
		res = gr->gr_name;
	}

	return (&res);
}
