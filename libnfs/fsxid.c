/*
 * This header file fakes the setfsuid call if we're on Linux
 * i386 and the call is not present in libc.
 */

#include "system.h"
#include "fsxid.h"

#ifdef NEEDS_FAKE_FSUID

/* stolen from /usr/include/asm/unistd.h */

int
setfsuid(uid_t fsuid)
{
	long __res;
	__asm__ volatile ("int $0x80":"=a" (__res)
			  :"0"(__NR_setfsuid), "b"((long) (fsuid)));

	if (__res >= 0) {
		return (int) __res;
	}
	errno = -__res;
	return -1;
}

int
setfsgid(gid_t fsgid)
{
	long __res;
	__asm__ volatile ("int $0x80":"=a" (__res)
			  :"0"(__NR_setfsgid), "b"((long) (fsgid)));

	if (__res >= 0) {
		return (int) __res;
	}
	errno = -__res;
	return -1;
}

#endif /* NEEDS_FAKE_FSUID */
