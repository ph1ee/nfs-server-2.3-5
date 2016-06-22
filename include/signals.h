/*
 * signals.h
 *
 * Portable signal handling installation.
 */

#ifndef UNFSD_SIGNALS_H_INCLUDED
#define UNFSD_SIGNALS_H_INCLUDED

/*
 * Global function prototypes.
 */

extern void install_signal_handler(int signo, RETSIGTYPE(*handler) (int));
extern void ignore_signal(int signo);

#endif /* UNFSD_SIGNALS_H_INCLUDED */
