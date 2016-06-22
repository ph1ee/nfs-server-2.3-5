/*
 * dispatch.c
 * 
 * This file contains the function dispatch table.
 *
 * Authors:	Donald J. Becker, <becker@super.org>
 *			Rick Sladkey, <jrs@world.std.com>
 *			Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *			Olaf Kirch, <okir@monad.swb.de>
 *
 * This software may be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 */

#include "nfsd.h"
#include "nfs_prot.h"
#include "rpcmisc.h"

#include "nfs_prot_xdr.c"

/*
 * These are the global variables that hold all argument and result data.
 */
union argument_types argument;
union result_types result;

/*
 * The time at which we received the request.
 * Useful for various book-keeping things
 */
time_t nfs_dispatch_time;

/*
 * This is a dispatch table to simplify error checking,
 * and supply return attributes for NFS functions.
 */

#ifdef __STDC__
#define CONCAT(a,b)	a##b
#define CONCAT3(a,b,c)	a##b##c
#define STRING(a)	#a
#else
#define CONCAT(a,b)	a/**/b
#define CONCAT3(a,b,c)	a/**/b/**/c
#define STRING(a)	"a"
#endif

#define table_ent(res_type, arg_type, funct) {		\
	sizeof(res_type), sizeof(arg_type),		\
	(xdrproc_t) CONCAT(xdr_,res_type),		\
	(xdrproc_t) CONCAT(xdr_,arg_type),		\
	(int (*)()) CONCAT3(nfsd_nfsproc_,funct,_2),	\
	STRING(funct), CONCAT(pr_,arg_type)		\
}

#define nil	void
#define xdr_nil	xdr_void
#define pr_nil	pr_void
#define pr_char	pr_void

struct dispatch_entry {
	size_t res_size;			       /* sizeof the res struct */
	size_t arg_size;			       /* sizeof the arg struct */
	xdrproc_t xdr_result;
	xdrproc_t xdr_argument;
	int (*funct) ();		       /* function handler      */
	char *name;			       /* name of function      */
	char *(*log_print) ();		       /* ptr to debug handler  */
};

static char *pr_void(void);
static char *pr_nfs_fh(nfs_fh * argp);
static char *pr_sattrargs(sattrargs * argp);
static char *pr_diropargs(diropargs * argp);
static char *pr_readargs(readargs * argp);
static char *pr_writeargs(writeargs * argp);
static char *pr_createargs(createargs * argp);
static char *pr_renameargs(renameargs * argp);
static char *pr_linkargs(linkargs * argp);
static char *pr_symlinkargs(symlinkargs * argp);
static char *pr_readdirargs(readdirargs * argp);

static struct dispatch_entry dtable[] = {
	table_ent(nil, nil, null),	       /* NULL */
	table_ent(attrstat, nfs_fh, getattr),  /* GETATTR */
	table_ent(attrstat, sattrargs, setattr),	/* SETATTR */
	table_ent(nil, nil, root),	       /* ROOT */
	table_ent(diropres, diropargs, lookup),	/* LOOKUP */
	table_ent(readlinkres, nfs_fh, readlink),	/* READLINK */
	table_ent(readres, readargs, read),    /* READ */
	table_ent(nil, nil, writecache),       /* WRITECACHE */
	table_ent(attrstat, writeargs, write), /* WRITE */
	table_ent(diropres, createargs, create),	/* CREATE */
	table_ent(nfsstat, diropargs, remove), /* REMOVE */
	table_ent(nfsstat, renameargs, rename),	/* RENAME */
	table_ent(nfsstat, linkargs, link),    /* LINK */
	table_ent(nfsstat, symlinkargs, symlink),	/* SYMLINK */
	table_ent(diropres, createargs, mkdir),	/* MKDIR */
	table_ent(nfsstat, diropargs, rmdir),  /* RMDIR */
	table_ent(readdirres, readdirargs, readdir),	/* READDIR */
	table_ent(statfsres, nfs_fh, statfs),  /* STATFS */
};

#ifdef ENABLE_CALL_PROFILING
#define PATH_PROFILE	"/tmp/nfsd.profile"

static struct timeval rtimes[18] = {
	{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0},
	{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0},
	{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}
};

static int calls[18] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static struct timeval t0, t1;

#endif /* ENABLE_CALL_PROFILING */

/*
 * The main dispatch routine.
 */
void
nfs_dispatch(struct svc_req *rqstp, SVCXPRT * transp)
{
	unsigned long proc_index = rqstp->rq_proc;
	struct dispatch_entry *dent;

	_rpcsvcdirty = 1;

	/*
	 * Reset our credentials to some sane default.
	 * Root privs will be needed in auth_fh/fh_find in order 
	 * to successfully stat() existing file handles
	 */

	auth_override_uid(root_uid);

	if (proc_index >= (sizeof(dtable) / sizeof(dtable[0]))) {
		svcerr_noproc(transp);
		goto done;
	}

	dent = &dtable[proc_index];

#ifdef ENABLE_CALL_PROFILING
	gettimeofday(&t0, NULL);
#endif /* ENABLE_CALL_PROFILING */

	/*
	 * Initialize our variables for determining the attributes of
	 * the file system in nfsd.c
	 */

	nfsclient = NULL;

	memset(&argument, 0, dent->arg_size);
	if (!svc_getargs(transp, (xdrproc_t) dent->xdr_argument, &argument)) {
		svcerr_decode(transp);
		goto done;
	}

	/* Clear the result structure. */
	memset(&result, 0, dent->res_size);

	/*
	 * Log the call. The if() saves us a superfluous call to the debug
	 * functions, which is a big performance win.
	 */

	if (log_level_enabled(D_CALL)) {
		log_call(__FILE__, __LINE__, rqstp, dent->name, dent->log_print(&argument));
	}

	/* Do the function call itself. */
	nfs_dispatch_time = time(NULL);
	result.nfsstat = (*dent->funct) (&argument, rqstp);

	if (log_level_enabled(D_CALL)) {
		dbg_printf(__FILE__, __LINE__, D_CALL, "result: %d\n", result.nfsstat);
	}

#if 0
	/* FIXME : either fix this, or pull it out. */
	if (!svc_sendreply(transp, dent->xdr_result, (caddr_t) & result)) {
		svcerr_systemerr(transp);
	}
#else
	svc_sendreply(transp, dent->xdr_result, (caddr_t) & result);
#endif

	if (!svc_freeargs(transp, (xdrproc_t) dent->xdr_argument, &argument)) {
		dbg_printf(__FILE__, __LINE__, L_ERROR,
			   "unable to free RPC arguments, exiting\n");
		exit(1);
	}

#ifdef ENABLE_CALL_PROFILING
	gettimeofday(&t1, NULL);

	if (t1.tv_usec < t0.tv_usec) {
		rtimes[proc_index].tv_sec += t1.tv_sec - t0.tv_sec - 1;
		rtimes[proc_index].tv_usec +=
			1000000 + t1.tv_usec - t0.tv_usec;
	} else {
		rtimes[proc_index].tv_sec += t1.tv_sec - t0.tv_sec;
		rtimes[proc_index].tv_usec += t1.tv_usec - t0.tv_usec;
	}

	calls[proc_index]++;
#endif /* ENABLE_CALL_PROFILING */

      done:
	_rpcsvcdirty = 0;

	if (nfsd_need_reinit()) {
		nfsd_reinitialize(0);
	}

	if (fh_need_flush()) {
		fh_flush_cache(0);
	}
}

#ifdef ENABLE_CALL_PROFILING

void
dump_stats(int sig)
{
	FILE *fp;
	int i;

	if ((fp = fopen(PATH_PROFILE, "w")) == NULL) {
		dbg_printf(__FILE__, __LINE__, L_WARNING,
			   "unable to write profile data to %s\n",
			   PATH_PROFILE);
		return;
	}

	for (i = 0; i < 18; i++) {
		float t;

		t = (float) rtimes[i].tv_sec +
			(float) rtimes[i].tv_usec / 1000000.0;
		fprintf(fp, "%-20s\t%5d calls %8.4f sec avg\n",
			dtable[i].name, calls[i],
			(calls[i]) ? t / calls[i] : 0);
		rtimes[i].tv_sec = rtimes[i].tv_usec = 0;
		calls[i] = 0;
	}

	fclose(fp);
}

#endif /* ENABLE_CALL_PROFILING */

/*
 * Functions for debugging output. This is still risky, because malformed
 * requests could overwrite our data segment.
 */
static char printbuf[2048];

static char *
pr_void(void)
{
	return ("");
}

static char *
pr_nfs_fh(nfs_fh * argp)
{
	return (fh_pr(argp));
}

static char *
pr_sattrargs(sattrargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"fh:%s m:%0o u/g:%ud/%ud size:%ud atime:%#x mtime:%#x",
		fh_pr(&argp->file),
		argp->attributes.mode,
		argp->attributes.uid,
		argp->attributes.gid,
		argp->attributes.size,
		argp->attributes.atime.seconds,
		argp->attributes.mtime.seconds);
	return (printbuf);
}

static char *
pr_diropargs(diropargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"fh:%s n:%s",
		fh_pr(&(argp->dir)),
		argp->name);
	return (printbuf);
}

static char *
pr_readargs(readargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"%s: %ud bytes at %ud",
		fh_pr(&argp->file),
		argp->count,
		argp->offset);
	return (printbuf);
}

static char *
pr_writeargs(writeargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"%s: %ud bytes at %ud",
		fh_pr(&argp->file),
		argp->data.data_len,
		argp->offset);
	return (printbuf);
}

static char *
pr_createargs(createargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"fh:%s n:%s m:%0o u/g:%ud/%ud size:%ud atime:%#x mtime:%#x",
		fh_pr(&argp->where.dir),	
		argp->where.name,
		argp->attributes.mode,
		argp->attributes.uid,
		argp->attributes.gid,
		argp->attributes.size,
		argp->attributes.atime.seconds,
		argp->attributes.mtime.seconds);
	return (printbuf);
}

static char *
pr_renameargs(renameargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"fh:%s n:%s -> fh:%s n:%s",
		fh_pr(&argp->from.dir),	
		argp->from.name,
		fh_pr(&argp->to.dir),
		argp->to.name);
	return (printbuf);
}

static char *
pr_linkargs(linkargs * argp)
{
	snprintf(printbuf, sizeof(printbuf),
		"fh:%s -> fh:%s n:%s",
		fh_pr(&argp->from),	
		fh_pr(&argp->to.dir),
		argp->to.name);
	return (printbuf);
}

static char *
pr_symlinkargs(symlinkargs * argp)
{
	return ("");
}

static char *
pr_readdirargs(readdirargs * argp)
{
	return (fh_pr(&argp->dir));
}
