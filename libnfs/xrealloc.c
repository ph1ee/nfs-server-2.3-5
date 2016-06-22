
/*
 * xrealloc.c -- realloc with "out of memory" checking
 * Copyright (C) 1990, 1991 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "system.h"
#include "xmalloc.h"

/*
 * Change the size of an allocated block of memory P to N bytes,
 * with error checking.
 * If P is NULL, run xmalloc.
 * If N is 0, run free and return NULL.
 */
void *
xrealloc(void *p, size_t n)
{
	if (p == 0) {
		return xmalloc(n);
	}
	if (n == 0) {
		free(p);
		return 0;
	}
	p = realloc(p, n);
	if (p == 0) {
		xmalloc_failed();
	}
	return p;
}
