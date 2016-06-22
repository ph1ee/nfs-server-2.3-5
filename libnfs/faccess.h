/* 
 * faccess.h
 *
 * Based on file of same name by Alexander O. Yuriev
 *
 * GNU General Public License Terms apply. All other rights reserved.
 */

#ifndef UNFSD_FACCESS_H_INCLUDED
#define UNFSD_FACCESS_H_INCLUDED

#define FACCESSOK		0
#define FACCESSWARN		1
#define FACCESSVIOL		2
#define	FACCESSNOTFOUND	3
#define FACCESSIOERR	4
#define FACCESSBADOWNER	5
#define FACCESSWRITABLE	6

int check_access(char *filename, uid_t uid, gid_t gid);

#endif /* UNFSD_FACCESS_H_INCLUDED */
