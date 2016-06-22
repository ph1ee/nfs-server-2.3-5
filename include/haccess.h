/*
 * haccess.h
 *
 * Wrapper for tcp_wrapper library
 */

#ifndef UNFSD_HACCESS_H_INCLUDED
#define UNFSD_HACCESS_H_INCLUDED

/*
 * Global function prototypes.
 */

extern int client_checkaccess(char *rpcprog, struct sockaddr_in *sin,
			      int checkport);
extern void client_flushaccess(void);

#endif /* UNFSD_HACCESS_H_INCLUDED */
