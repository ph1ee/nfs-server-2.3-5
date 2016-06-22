/*
 * rpcmisc	Support for RPC startup and shutdown.
 */

#ifndef UNFSD_RPCMISC_H_INCLUDED
#define UNFSD_RPCMISC_H_INCLUDED

/*
 * Global variables.
 */

extern int _rpcpmstart;
extern int _rpcfdtype;
extern int _rpcsvcdirty;
extern const char *auth_daemon;

/*
 * Global function prototypes.
 */

extern void rpc_init(const char *name, unsigned long prog, unsigned long *verstbl,
		     void (*dispatch) (), in_port_t defport, int bufsize);
extern void rpc_exit(unsigned long prog, unsigned long *verstbl);
extern void rpc_closedown(void);

/*
 * Should be delcared in xdr.h, but sometimes isn't.
 */

#if !defined(HAVE_XDR_FREE_DECL)
extern void xdr_free(xdrproc_t proc, char *objp);
#endif /* ! HAVE_XDR_FREE_DECL */

#endif /* UNFSD_RPCMISC_H_INCLUDED */
