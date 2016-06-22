/*
 * getattr.c
 *
 * This module handles the NFS attributes.
 *
 * Authors:	Mark A. Shand, May 1988
 *			Donald J. Becker, <becker@super.org>
 *			Rick Sladkey, <jrs@world.std.com>
 *			Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Copyright 1988 Mark A. Shand
 *
 * This software maybe be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 */

#include "nfsd.h"

#ifdef S_SPLINT_S
#define major(m) m
#define minor(m) m
#endif /* S_SPLINT_S */

/*
 * The NFS version 2 specification fails to mention all of
 * these file types, but they exist in the nfs_prot.x file.
 */
#define ftype_map(st_mode) (_ftype_map[((st_mode) & S_IFMT) >> 12])

ftype _ftype_map[16] = {
#ifdef S_IFIFO
	NFNON, NFFIFO, NFCHR, NFBAD,
#else
	NFNON, NFBAD, NFCHR, NFBAD,
#endif
	NFDIR, NFBAD, NFBLK, NFBAD,
	NFREG, NFBAD, NFLNK, NFBAD,
	NFSOCK, NFBAD, NFBAD, NFBAD,
};

/*
 * Get file attributes based on file handle
 */
nfsstat
fh_getattr(nfs_fh * fh, fattr * attr, struct stat *stat_optimize,
	   struct svc_req *rqstp)
{
	fhcache *fhc;

	if ((fhc = fh_find((svc_fh *) fh, FHFIND_FEXISTS)) == NULL) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "getattr: failed! No such file.\n");
		return (NFSERR_STALE);
	}

	return fhc_getattr(fhc, attr, stat_optimize, rqstp);
}

dev_t
st_rdev(struct stat* s)
{
#ifdef __CYGWIN__
	/* This assumes we're on a cygwin system, and exporting
	 * to a linux system.  YMMV.
	 */
	dev_t major = major(s->st_rdev);
	dev_t minor = minor(s->st_rdev);
	return (dev_t) ((minor & 0xff) | ((major & 0xfff) << 8)
		| (((unsigned long long int) (minor & ~0xff)) << 12)
		| (((unsigned long long int) (major & ~0xfff)) << 32));
#else
	return s->st_rdev;
#endif /* __CYGWIN__ */
}

/*
 * Get file attributes given the path.
 */
nfsstat
fhc_getattr(fhcache * fhc, fattr * attr, struct stat * stat_optimize,
	    struct svc_req * rqstp)
{
	struct stat *s;
	struct stat sbuf;

	memset(&sbuf, 0, sizeof(&sbuf));

	if (stat_optimize != NULL && stat_optimize->st_nlink != 0) {
		s = stat_optimize;
	} else if (lstat(fhc->path, (s = &sbuf)) != 0) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "getattr(%s): failed!  errno=%d\n", fhc->path,
			   errno);
		return nfs_errno();
	}

	attr->type  = ftype_map(s->st_mode);
	attr->mode  = (u_int) s->st_mode;
	attr->nlink = (u_int) s->st_nlink;
	attr->uid   = (u_int) ruid(s->st_uid, nfsmount, rqstp);
	attr->gid   = (u_int) rgid(s->st_gid, nfsmount, rqstp);

	/* Some applications need the exact symlink size */

#if defined(S_ISLNK)
	if (S_ISLNK(s->st_mode)) {
		attr->size = MIN(s->st_size, NFS_MAXPATHLEN);
	} else {
		attr->size = s->st_size;
	}
#else
	attr->size = (u_int) s->st_size;
#endif /* S_ISLNK */

#if defined(HAVE_STRUCT_STAT_ST_BLKSIZE)
	attr->blocksize = s->st_blksize;
#elif defined(BUFSIZ)
	attr->blocksize = BUFSIZ;
#else
	attr->blocksize = 1024;
#endif /* !BUFSIZ */

#ifdef HAVE_STRUCT_STAT_ST_RDEV
	attr->rdev = (u_int) st_rdev(s);
#else
	attr->rdev = (u_int) s->st_size;
#endif /* HAVE_STRUCT_STAT_ST_RDEV */

#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
	attr->blocks = (u_int) s->st_blocks;
#else
	attr->blocks = st_blocks(s);
#endif /* HAVE_STRUCT_STAT_ST_BLOCKS */

#if 0
	/* FIXME: either figure out why this was here, or ditch it */
	if (nfsmount->o.cross_mounts) {
		attr->fsid = 1;
		attr->fileid = fh_psi((nfs_fh *) & (fhc->h));
	} else {
		attr->fsid = s->st_dev;
		attr->fileid = covered_ino(fhc->path);
	}
#else
	attr->fsid = 1;
	attr->fileid = (u_int) fh_psi((nfs_fh *) & (fhc->h));
#endif

	attr->atime.seconds  = (u_int) s->st_atime;
	attr->atime.useconds = 0;
	attr->mtime.seconds  = (u_int) s->st_mtime;
	attr->mtime.useconds = 0;
	attr->ctime.seconds  = (u_int) s->st_ctime;
	attr->ctime.useconds = 0;

	return (NFS_OK);
}
