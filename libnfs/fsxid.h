/*
 * This header file fakes the setfsuid call if we're on Linux
 * i386 and the call is not present in libc.
 */

#if defined(HAVE_SETFSUID)

#define FSUID_PRESENT
#undef  NEEDS_FAKE_FSUID

#elif defined(HAVE_SYS_FSUID_H)

#include <sys/fsuid.h>
#define FSUID_PRESENT
#undef  NEEDS_FAKE_FSUID

#elif defined(linux) && defined(i386)

#include <linux/unistd.h>
#define FSUID_PRESENT
#define NEEDS_FAKE_FSUID

#else

#undef FSUID_PRESENT
#undef NEEDS_FAKE_FSUID

#endif /* defined(linux) && defined(i386) && !defined(HAVE_SETFSUID) */
