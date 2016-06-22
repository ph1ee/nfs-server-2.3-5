
/*
 * rmtab.h	Support for rmtab manipulations.
 */

#ifndef UNFSD_RMTAB_H
#define UNFSD_RMTAB_H

/*
 * Location of rmtab file.
 * /etc/rmtab is the standard on most systems.
 */
#include <paths.h>

#ifndef _PATH_RMTAB
#define _PATH_RMTAB	"/etc/rmtab"
#endif

#include <rpc/rpc.h>
#include <rpc/svc.h>
#include "mount.h"

extern void rmtab_add_client(dirpath path, struct svc_req *rqstp);
extern mountlist *rmtab_lst_client(void);
extern void rmtab_del_client(dirpath path, struct svc_req *rqstp);
extern void rmtab_mdel_client(struct svc_req *rqstp);

#endif /* UNFSD_RMTAB_H */
