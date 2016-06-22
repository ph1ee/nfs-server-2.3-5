/*
 * xrealpath.h
 *
 * Wrapper for internal implmentation of realpath()
 */

#ifndef UNFSD_XREALPATH_H_INCLUDED
#define UNFSD_XREALPATH_H_INCLUDED

#if defined(HAVE_REALPATH) && !defined(__CYGWIN__)
#define xrealpath realpath
#else
#ifdef __STDC__
char * xrealpath(const char *path, char resolved_path []);
#else
char * xrealpath();
#endif /* __STDC__ */
#endif /* HAVE_REALPATH && !__CYGWIN__ */

#endif /* UNFSD_XREALPATH_H_INCLUDED */
