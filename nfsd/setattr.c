/*
 * setattr.c
 *
 * This module handles the NFS attributes.
 *
 * Authors:	Mark A. Shand, May 1988
 *			Donald J. Becker, <becker@super.org>
 *			Rick Sladkey, <jrs@world.std.com>
 *			Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *			Olaf Kirch, <okir@monad.swb.de>
 *
 * Copyright 1988 Mark A. Shand
 *
 * This software maybe be used for any purpose provided
 * the above copyright notice is retained.  It is supplied
 * as is, with no warranty expressed or implied.
 */

#include "nfsd.h"

#define IGNORE_TIME	((unsigned int) -1)

/*
 * Set file attributes based on file handle
 */
nfsstat
fh_setattr(nfs_fh * fh, sattr * attr, struct stat *s,
	   struct svc_req *rqstp, int flags)
{
	char *path;
	nfsstat status;

	if ((path = fh_path(fh, &status)) == NULL) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "setattr failed: No such file.\n");
		return (NFSERR_STALE);
	}

	return setattr(path, attr, s, rqstp, flags);
}

/*
 * Set file attributes given the path. The flags argument
 * determines if we have to stat the file or if the stat buf
 * passed in s contains valid data.
 * As we go along and modify the file attributes, we update the
 * fields of this stat structure.
 */
nfsstat
setattr(char *path, sattr * attr, struct stat * s,
	struct svc_req * rqstp, int flags)
{
	struct stat sbuf;

	if (s == NULL) {
		s = &sbuf;
		flags |= SATTR_STAT;
	}

	if ((flags & SATTR_STAT) && lstat(path, (s = &sbuf)) < 0) {
		dbg_printf(__FILE__, __LINE__, D_CALL,
			   "setattr: couldn't stat %s! errno=%d\n", path,
			   errno);
		return nfs_errno();
	}

	if (flags & SATTR_SIZE) {
		unsigned int size = attr->size;

		if (S_ISREG(s->st_mode) && size != (unsigned int) -1) {
			if (truncate(path, size) < 0) {
				return nfs_errno();
			}
			s->st_size = size;
		}
	}

	if (flags & SATTR_UTIMES) {
		unsigned int atime_secs = attr->atime.seconds;
		unsigned int mtime_secs = attr->mtime.seconds;

		if ((atime_secs != IGNORE_TIME && atime_secs != (unsigned int) s->st_atime)
		    || (mtime_secs != IGNORE_TIME && mtime_secs != (unsigned int) s->st_mtime)) {
			struct timeval tvp[2];

			/*
			 * Cover for partial utime setting
			 * Alan Cox <alan@redhat.com>
			 */
			/*
			 * Turn off type checking; cygwin timeval members are
			 * signed types (ech.)
			 */
#ifdef __CYGWIN__
			/*@ -type @*/ 
#endif /* __CYGWIN__ */
			if (atime_secs != IGNORE_TIME) {
				tvp[0].tv_sec = attr->atime.seconds;
				tvp[0].tv_usec = attr->atime.useconds;
				s->st_atime = attr->atime.seconds;
			} else {
				tvp[0].tv_sec = s->st_atime;
				tvp[0].tv_usec = 0;
			}
			if (mtime_secs != IGNORE_TIME) {
				tvp[1].tv_sec = attr->mtime.seconds;
				tvp[1].tv_usec = attr->mtime.useconds;
				s->st_mtime = attr->mtime.seconds;
			} else {
				tvp[1].tv_sec = s->st_mtime;
				tvp[1].tv_usec = 0;
			}
#ifdef __CYGWIN__
			/*@ =type @*/ 
#endif /* __CYGWIN__ */

			if (utimes(path, tvp) < 0) {
				return nfs_errno();
			}
		}
	}

	if (flags & SATTR_CHMOD) {
		mode_t mode = (mode_t) attr->mode;

		if (mode != -1 && mode != 0xFFFF	/* ultrix bug */
		    && (mode & 07777) != (s->st_mode & 07777)) {
			if (chmod(path, mode) < 0) {
				return nfs_errno();
			}
			s->st_mode = (s->st_mode & ~07777) | (mode & 07777);
		}
	}

	if (flags & SATTR_CHOWN) {
		uid_t uid = attr->uid;
		gid_t gid = attr->gid;

		if (uid != (uid_t) - 1) {
			uid = luid(uid, nfsmount, rqstp);
		}

		if (gid != (gid_t) - 1) {
			gid = lgid(gid, nfsmount, rqstp);
		}

		if ((uid != (uid_t) - 1 && uid != s->st_uid)
		    || (gid != (gid_t) - 1 && gid != s->st_gid)) {
			if (lchown(path, uid, gid) < 0) {
				return nfs_errno();
			}
			if (uid != (uid_t) - 1) {
				s->st_uid = uid;
			}
			if (gid != (gid_t) - 1) {
				s->st_gid = gid;
			}
		}
	}

	return (NFS_OK);
}
