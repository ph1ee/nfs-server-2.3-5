/*
 * Device table index.
 */

#ifndef UNFSD_DEVTAB_H_INCLUDED
#define UNFSD_DEVTAB_H_INCLUDED

#ifdef ENABLE_DEVTAB
unsigned int devtab_index(dev_t dev);
#endif

#endif
