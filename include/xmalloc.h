/*
 * xmalloc.h
 *
 * Prototypes for memory allocation functions that include
 * "out of memory" checking.
 */

#ifndef UNFSD_XMALLOC_H_INCLUDED
#define UNFSD_XMALLOC_H_INCLUDED

/*
 * Global function prototypes.
 */

extern void *xmalloc(size_t n);
extern void *xrealloc(void *ptr, size_t n);
extern char *xstrdup(const char *str);
extern void xmalloc_failed(void);

#endif /* UNFSD_XMALLOC_H_INCLUDED */
