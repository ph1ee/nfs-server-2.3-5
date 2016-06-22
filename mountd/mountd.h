/*
 * mountd.h	This program implements a user-space NFS server.
 *
 * Authors:	Mark A. Shand, May 1988
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		Copyright 1988 Mark A. Shand
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#ifndef UNFSD_MOUNTD_H
#define UNFSD_MOUNTD_H

#include "system.h"
#include "mount.h"
#include "nfs_prot.h"

#define MOUNT_PORT 0

union argument_types {
	dirpath dirpath;
};

union result_types {
	fhstatus fstatus;
	mountlist mountlist;
	exports exports;
	pathcnf pathconf;
};

/*
 * Global variables.
 */
extern union argument_types argument;
extern union result_types result;
extern int need_reinit;

/*
 * Include the other module definitions.
 */
#include "auth.h"
#include "fhandle.h"
#include "logging.h"

/*
 * Global Function prototypes.
 */
extern void mount_dispatch(struct svc_req *, SVCXPRT *);
extern RETSIGTYPE reinitialize(int sig);

#endif /* UNFSD_MOUNTD_H */
