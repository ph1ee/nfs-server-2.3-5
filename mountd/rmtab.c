
/*
 * A set of support routines for /etc/rmtab file managment. These routines
 * are called from mountd.c.
 *
 * Written and Copyright by Dariush Shirazi, <dshirazi@uhl.uiowa.edu>
 *
 */

#include "system.h"
#include "xmalloc.h"
#include "rmtab.h"
#include "logging.h"

static char *rmtab_gethost(struct svc_req *rqstp);
static int rmtab_insert(char *hostname, char *path);
static void rmtab_read_file(void);
static void rmtab_write_file(void);

/*
 * global top to linklist
 */
static mountlist rmtablist = NULL;

/*
 * Cached last modified time for rmtab
 */
static time_t old_rmtab_mtime = 0;

/*
 * rmtab_add_client -- if client+path not in the list, add them.
 */
void
rmtab_add_client(dirpath path, struct svc_req *rqstp)
{
	char *hostname;

	hostname = rmtab_gethost(rqstp);

	if (hostname != NULL) {
		dbg_printf(__FILE__, __LINE__, D_RMTAB,
			   "\trmtab_add_client path='%s' host='%s'\n", path,
			   hostname);
		rmtab_read_file();
		if (rmtab_insert(hostname, path)) {
			rmtab_write_file();
		}
	}
}

/*
 * rmtab_lst_client -- return the top pointer.
 */
mountlist *
rmtab_lst_client(void)
{
	rmtab_read_file();
	return (&rmtablist);
}

/*
 * rmtab_del_client -- delete a client+path
 */
void
rmtab_del_client(dirpath path, struct svc_req *rqstp)
{
	int p0;
	int p1;
	int changed;
	char *hostname;
	mountlist cur;
	mountlist prv;

	hostname = rmtab_gethost(rqstp);

	if (hostname == NULL) {
		return;
	}

	dbg_printf(__FILE__, __LINE__, D_RMTAB,
		   "\trmtab_del_client path='%s' host='%s'\n", path,
		   hostname);
	rmtab_read_file();

	changed = 0;

	for (cur = rmtablist, prv = NULL; cur; cur = cur->ml_next) {
		p0 = strcmp(cur->ml_hostname, hostname);
		p1 = strcmp(cur->ml_directory, path);

		if (p0 == 0 && p1 == 0) {
			/* already exists */
			break;
		}

		prv = cur;
	}

	if (cur) {
		/*
		 * don't free both ml_hostname & ml_directory.
		 * See rmtab_insert for details.
		 */

		free(cur->ml_hostname);

		if (prv) {
			prv->ml_next = cur->ml_next;
		} else {
			rmtablist = cur->ml_next;
		}

		free(cur);

		changed = 1;
	}

	if (changed) {
		rmtab_write_file();
	}
}

/*
 * rmtab_mdel_client -- delete all the entry points for a client
 */
void
rmtab_mdel_client(struct svc_req *rqstp)
{
	int p0;
	int changed;
	char *hostname;
	mountlist cur;
	mountlist prv;
	mountlist tmp;

	hostname = rmtab_gethost(rqstp);

	if (hostname == NULL) {
		return;
	}

	dbg_printf(__FILE__, __LINE__, D_RMTAB,
		   "\trmtab_mdel_client host='%s'\n", hostname);
	rmtab_read_file();

	changed = 0;
	prv = NULL;
	cur = rmtablist;

	while (cur) {
		p0 = strcmp(cur->ml_hostname, hostname);

		if (p0 == 0) {
			/*
			 * don't free both ml_hostname & ml_directory.
			 * See rmtab_insert for details.
			 */
			tmp = cur;
			cur = cur->ml_next;

			if (prv) {
				prv->ml_next = cur;
			} else {
				rmtablist = cur;
			}

			free(tmp->ml_hostname);
			free(tmp);

			changed = 1;
		} else if (p0 < 0) {
			prv = cur;
			cur = cur->ml_next;
		} else {
			/* not found */
			break;
		}
	}

	if (changed) {
		rmtab_write_file();
	}
}

/*
 * rmtab_gethost -- return the hostname
 */
static char *
rmtab_gethost(struct svc_req *rqstp)
{
	struct hostent *hp;
	struct in_addr addr;

	addr = svc_getcaller(rqstp->rq_xprt)->sin_addr;
	hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);

	if (hp) {
		return ((char *) hp->h_name);
	}

	return ((char*) inet_ntoa(addr));
}

/*
 * rmtab_insert -- a sorted link list
 */
static int
rmtab_insert(char *hostname, char *path)
{
	size_t hostlen;
	int p0;
	int p1;
	mountlist cur;
	mountlist prv;

	for (cur = rmtablist, prv = NULL; cur; cur = cur->ml_next) {
		p0 = strcmp(cur->ml_hostname, hostname);
		p1 = strcmp(cur->ml_directory, path);

		if (p0 > 0 || (p0 == 0 && p1 > 0)) {
			/* insert here */
			break;
		} else if (p0 == 0 && p1 == 0) {
			/* already exists */
			return (0);
		}

		prv = cur;
	}

	cur = (mountlist) xmalloc(sizeof(mountbody));

	/*
	 * since the data we are storing is really small (ie. h.x.y.z:/cur),
	 * allocate one memory unit for both and split it.
	 */
	hostlen = strlen(hostname);

	cur->ml_hostname = (char *) xmalloc(hostlen + strlen(path) + 2);
	cur->ml_directory = cur->ml_hostname + (hostlen + 1);

	strcpy(cur->ml_hostname, hostname);
	strcpy(cur->ml_directory, path);

	if (prv) {
		cur->ml_next = prv->ml_next;
		prv->ml_next = cur;
	} else {
		cur->ml_next = rmtablist;
		rmtablist = cur;
	}

	return (1);
}

/*
 * rmtab_read_file -- read the mount list from /etc/rmtab.
 */
static void
rmtab_read_file(void)
{
	register int c;
	register int len;
	register char *p;
	char buff[256];
	char *host;
	char *path;
	FILE *fp;
	mountlist cur;
	struct stat newstat;

	/* get a new stat; if file not there, create it */

	if (stat(_PATH_RMTAB, &newstat)) {
		int zappa;

		if ((zappa = creat(_PATH_RMTAB, 0644)) < 0) {
			dbg_printf(__FILE__, __LINE__, L_ERROR,
				   "failed to create '%s'\n", _PATH_RMTAB);
			umask(0);
			return;
		}

		close(zappa);
		umask(0);

		if (stat(_PATH_RMTAB, &newstat)) {
			dbg_printf(__FILE__, __LINE__, L_ERROR,
				   "failed to stat '%s'\n", _PATH_RMTAB);
			return;
		}

		old_rmtab_mtime = newstat.st_mtime;
		return;
	}

	if (old_rmtab_mtime == newstat.st_mtime) {
		/* no change */
		return;
	}

	if ((fp = fopen(_PATH_RMTAB, "r")) == NULL) {
		dbg_printf(__FILE__, __LINE__, L_ERROR,
			   "failed to open '%s'\n", _PATH_RMTAB);
		return;
	}

	/* free the old list */

	while (rmtablist) {
		cur = rmtablist;
		rmtablist = rmtablist->ml_next;

		/*
		 * don't free both ml_hostname & ml_directory.
		 * See rmtab_insert for details.
		 */

		free(cur->ml_hostname);
		free(cur);
	}

	while (!feof(fp)) {
		/*
		 * the reason this looks worse than it should is so
		 * we don't have to do bunch of passes on the buff.
		 * (fgets,strlen,strchr...)
		 */

		p = buff;
		host = buff;
		path = NULL;
		len = c = 0;

		while (!feof(fp) && (c = fgetc(fp)) != '\n' && len < 255) {
			if (c == ':') {
				c = '\0';
				path = p + 1;
			}
			*p++ = (char) c;
			len++;
		}

		*p = '\0';

		while (!feof(fp) && c != '\n') {	/* skip if line > 255 */
			c = fgetc(fp);
		}

		if (path) {	/* skip bad input */
			if (*host && *path) {
				rmtab_insert(host, path);
			}
		}
	}

	fclose(fp);
	old_rmtab_mtime = newstat.st_mtime;
}

/*
 * rmtab_write_file -- write the mount list to /etc/rmtab.
 */
static void
rmtab_write_file(void)
{
	FILE *fp;
	mountlist cur;
	struct stat newstat;

	if ((fp = fopen(_PATH_RMTAB, "w")) == NULL) {
		dbg_printf(__FILE__, __LINE__, L_ERROR,
			   "failed to open '%s'\n", _PATH_RMTAB);
		return;
	}

	for (cur = rmtablist; cur; cur = cur->ml_next) {
		fprintf(fp, "%s:%s\n", cur->ml_hostname, cur->ml_directory);
	}

	fclose(fp);

	if (stat(_PATH_RMTAB, &newstat)) {
		dbg_printf(__FILE__, __LINE__, L_ERROR,
			   "failed to stat '%s'\n", _PATH_RMTAB);
		fclose(fp);
		return;
	}

	old_rmtab_mtime = newstat.st_mtime;
}
