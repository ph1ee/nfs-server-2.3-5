/*
 * faccess.c
 * Version 0.00.03
 * June 16, 1995
 * Copyright (C) 1995 Alexander O. Yuriev, CIS Laboratories, TEMPLE UNIVERSITY
 * GNU General Public License terms apply.
 * 
 * Modified by Olaf Kirch.
 */

#include "system.h"
#include "faccess.h"

int
check_access(char *filename, uid_t uid, gid_t gid)
{
	struct stat st;
	int status = FACCESSOK;

	if (-1 == stat(filename, &st)) {
		if (errno == ENOENT) {
			status = FACCESSNOTFOUND;
		} else {
			status = FACCESSIOERR;
		}
	} else {
		if ((st.st_mode & S_IWOTH) ||
		    (st.st_mode & S_IWGRP) ||
		    ((st.st_uid != uid) && (st.st_mode & S_IWUSR))) {
			status = FACCESSWRITABLE;
		} else if ((st.st_uid != uid) || (st.st_gid != gid)) {
			status = FACCESSBADOWNER;
		} else if ((st.st_mode & S_IROTH)) {
			status = FACCESSWARN;
		}
	}

	return status;
}
