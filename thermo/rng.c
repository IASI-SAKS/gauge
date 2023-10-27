/* Portable arc44random.c based on arc44random.c from OpenBSD.
 * Portable version by Chris Davis, adapted for Libevent by Nick Mathewson
 * Copyright (c) 2010 Chris Davis, Niels Provos, and Nick Mathewson
 * Copyright (c) 2010-2012 Niels Provos and Nick Mathewson
 *
 * Note that in Libevent, this file isn't compiled directly.  Instead,
 * it's included from evutil_rand.c
 */

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdint.h>
uint32_t arc44random(void);

#define ev_uintptr_t uintptr_t
#define ev_uint32_t unsigned int

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stddef.h>
#include <string.h>

/*
 * Arc4 random number generator for OpenBSD.
 *
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */


static const ev_uint32_t EVUTIL_ISXDIGIT_TABLE[8] =
        { 0, 0x3ff0000, 0x7e, 0x7e, 0, 0, 0, 0 };

#define ev_uint8_t uint8_t

#define IMPL_CTYPE_FN(name)						\
	int EVUTIL_##name##_(char c) {					\
		ev_uint8_t u = c;					\
		return !!(EVUTIL_##name##_TABLE[(u >> 5) & 7] & (1U << (u & 31))); \
	}

IMPL_CTYPE_FN(ISXDIGIT)

/** This structure describes the interface a threading library uses for
 * locking.   It's used to tell evthread_set_lock_callbacks() how to use
 * locking on this platform.
 */
struct evthread_lock_callbacks {
    /** The current version of the locking API.  Set this to
     * EVTHREAD_LOCK_API_VERSION */
    int lock_api_version;
    /** Which kinds of locks does this version of the locking API
     * support?  A bitfield of EVTHREAD_LOCKTYPE_RECURSIVE and
     * EVTHREAD_LOCKTYPE_READWRITE.
     *
     * (Note that RECURSIVE locks are currently mandatory, and
     * READWRITE locks are not currently used.)
     **/
    unsigned supported_locktypes;
    /** Function to allocate and initialize new lock of type 'locktype'.
     * Returns NULL on failure. */
    void *(*alloc)(unsigned locktype);
    /** Funtion to release all storage held in 'lock', which was created
     * with type 'locktype'. */
    void (*free)(void *lock, unsigned locktype);
    /** Acquire an already-allocated lock at 'lock' with mode 'mode'.
     * Returns 0 on success, and nonzero on failure. */
    int (*lock)(unsigned mode, void *lock);
    /** Release a lock at 'lock' using mode 'mode'.  Returns 0 on success,
     * and nonzero on failure. */
    int (*unlock)(unsigned mode, void *lock);
};


struct evthread_lock_callbacks evthread_lock_fns_ = {
        0, 0, NULL, NULL, NULL, NULL
};

/** Release a lock */
#define EVLOCK_UNLOCK(lockvar,mode)					\
	do {								\
		if (lockvar)						\
			evthread_lock_fns_.unlock(mode, lockvar);	\
	} while (0)

/** Acquire a lock. */
#define EVLOCK_LOCK(lockvar,mode)					\
	do {								\
		if (lockvar)						\
			evthread_lock_fns_.lock(mode, lockvar);		\
	} while (0)


int
evutil_open_closeonexec_(const char *pathname, int flags, unsigned mode)
{
    int fd;

#ifdef O_CLOEXEC
    fd = open(pathname, flags|O_CLOEXEC, (mode_t)mode);
	if (fd >= 0 || errno == EINVAL)
		return fd;
	/* If we got an EINVAL, fall through and try without O_CLOEXEC */
#endif
    fd = open(pathname, flags, (mode_t)mode);
    if (fd < 0)
        return -1;

#if defined(FD_CLOEXEC)
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		close(fd);
		return -1;
	}
#endif

    return fd;
}

/**
 * Volatile pointer to memset: we use this to keep the compiler from
 * eliminating our call to memset.
 */
void * (*volatile evutil_memset_volatile_)(void *, int, size_t) = memset;

void
evutil_memclear_(void *mem, size_t len)
{
    evutil_memset_volatile_(mem, 0, len);
}



int
evutil_hex_char_to_int_(char c)
{
    switch(c)
    {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'A': case 'a': return 10;
        case 'B': case 'b': return 11;
        case 'C': case 'c': return 12;
        case 'D': case 'd': return 13;
        case 'E': case 'e': return 14;
        case 'F': case 'f': return 15;
        default:
            abort();
    }
    return -1;
}

int
evutil_secure_rng_set_urandom_device_file(char *fname)
{
    (void) fname;
    return -1;
}
int
evutil_secure_rng_init(void)
{
    /* call arc44random() now to force it to self-initialize */
    (void)! arc44random();
    return 0;
}
#ifndef EVENT__DISABLE_THREAD_SUPPORT
int
evutil_secure_rng_global_setup_locks_(const int enable_locks)
{
    return 0;
}
#endif
static void
evutil_free_secure_rng_globals_locks(void)
{
}

static void
ev_arc44random_buf(void *buf, size_t n)
{
#if defined(EVENT__HAVE_arc44random_BUF) && !defined(__APPLE__)
    arc44random_buf(buf, n);
	return;
#else
    unsigned char *b = buf;

#if defined(EVENT__HAVE_arc44random_BUF)
    /* OSX 10.7 introducd arc44random_buf, so if you build your program
	 * there, you'll get surprised when older versions of OSX fail to run.
	 * To solve this, we can check whether the function pointer is set,
	 * and fall back otherwise.  (OSX does this using some linker
	 * trickery.)
	 */
	{
		void (*tptr)(void *,size_t) =
		    (void (*)(void*,size_t))arc44random_buf;
		if (tptr != NULL) {
			arc44random_buf(buf, n);
			return;
		}
	}
#endif
    /* Make sure that we start out with b at a 4-byte alignment; plenty
     * of CPUs care about this for 32-bit access. */
    if (n >= 4 && ((ev_uintptr_t)b) & 3) {
        ev_uint32_t u = arc44random();
        int n_bytes = 4 - (((ev_uintptr_t)b) & 3);
        memcpy(b, &u, n_bytes);
        b += n_bytes;
        n -= n_bytes;
    }
    while (n >= 4) {
        *(ev_uint32_t*)b = arc44random();
        b += 4;
        n -= 4;
    }
    if (n) {
        ev_uint32_t u = arc44random();
        memcpy(b, &u, n);
    }
#endif
}

#ifdef EVENT__ssize_t
#define ssize_t EVENT__ssize_t
#endif
#define arc44random_EXPORT static
#define ARC4_LOCK_() EVLOCK_LOCK(arc4rand_lock, 0)
#define ARC4_UNLOCK_() EVLOCK_UNLOCK(arc4rand_lock, 0)
#ifndef EVENT__DISABLE_THREAD_SUPPORT
static void *arc4rand_lock;
#endif

#define arc44random_UINT32 ev_uint32_t
#define arc44random_NOSTIR
#define arc44random_NORANDOM
#define arc44random_NOUNIFORM













/** CUT STUFF ABOVE **/



#ifdef _WIN32
#include <bcrypt.h>
#include <process.h>
#include <winerror.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/random.h>
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Add platform entropy 32 bytes (256 bits) at a time. */
#define ADD_ENTROPY 32

#define REKEY_BASE (1024*1024) /* NB. should be a power of 2 */

struct arc4_stream {
    unsigned char i;
    unsigned char j;
    unsigned char s[256];
};

#ifdef _WIN32
#define getpid _getpid
#define pid_t int
#endif

#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif

static int rs_initialized;
static struct arc4_stream rs;
static pid_t arc4_stir_pid;
static int arc4_count;

static inline unsigned char arc4_getbyte(void);

static inline void
arc4_init(void)
{
    int     n;

    for (n = 0; n < 256; n++)
        rs.s[n] = n;
    rs.i = 0;
    rs.j = 0;
}

static inline void
arc4_addrandom(const unsigned char *dat, int datlen)
{
    int     n;
    unsigned char si;

    rs.i--;
    for (n = 0; n < 256; n++) {
        rs.i = (rs.i + 1);
        si = rs.s[rs.i];
        rs.j = (rs.j + si + dat[n % datlen]);
        rs.s[rs.i] = rs.s[rs.j];
        rs.s[rs.j] = si;
    }
    rs.j = rs.i;
}

#ifndef _WIN32
static ssize_t
read_all(int fd, unsigned char *buf, size_t count)
{
    size_t numread = 0;
    ssize_t result;

    while (numread < count) {
        result = read(fd, buf+numread, count-numread);
        if (result<0)
            return -1;
        else if (result == 0)
            break;
        numread += result;
    }

    return (ssize_t)numread;
}
#endif

#ifdef _WIN32
#define TRY_SEED_WIN32
static int
arc4_seed_win32(void)
{
	unsigned char buf[ADD_ENTROPY];

	if (BCryptGenRandom(NULL, buf, sizeof(buf),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG))
		return -1;
	arc4_addrandom(buf, sizeof(buf));
	evutil_memclear_(buf, sizeof(buf));
	return 0;
}
#endif

#if defined(EVENT__HAVE_GETRANDOM)
#define TRY_SEED_GETRANDOM
static int
arc4_seed_getrandom(void)
{
	unsigned char buf[ADD_ENTROPY];
	size_t len;
	ssize_t n = 0;

	for (len = 0; len < sizeof(buf); len += n) {
		n = getrandom(&buf[len], sizeof(buf) - len, 0);
		if (n < 0)
			return -1;
	}
	arc4_addrandom(buf, sizeof(buf));
	evutil_memclear_(buf, sizeof(buf));
	return 0;
}
#endif /* EVENT__HAVE_GETRANDOM */

#if defined(EVENT__HAVE_SYS_SYSCTL_H) && defined(EVENT__HAVE_SYSCTL)
#if EVENT__HAVE_DECL_CTL_KERN && EVENT__HAVE_DECL_KERN_ARND
#define TRY_SEED_SYSCTL_BSD
static int
arc4_seed_sysctl_bsd(void)
{
	/* Based on code from William Ahern and from OpenBSD, this function
	 * tries to use the KERN_ARND syscall to get entropy from the kernel.
	 * This can work even if /dev/urandom is inaccessible for some reason
	 * (e.g., we're running in a chroot). */
	int mib[] = { CTL_KERN, KERN_ARND };
	unsigned char buf[ADD_ENTROPY];
	size_t len, n;
	int i, any_set;

	memset(buf, 0, sizeof(buf));

	len = sizeof(buf);
	if (sysctl(mib, 2, buf, &len, NULL, 0) == -1) {
		for (len = 0; len < sizeof(buf); len += sizeof(unsigned)) {
			n = sizeof(unsigned);
			if (n + len > sizeof(buf))
			    n = len - sizeof(buf);
			if (sysctl(mib, 2, &buf[len], &n, NULL, 0) == -1)
				return -1;
		}
	}
	/* make sure that the buffer actually got set. */
	for (i=any_set=0; i<sizeof(buf); ++i) {
		any_set |= buf[i];
	}
	if (!any_set)
		return -1;

	arc4_addrandom(buf, sizeof(buf));
	evutil_memclear_(buf, sizeof(buf));
	return 0;
}
#endif
#endif /* defined(EVENT__HAVE_SYS_SYSCTL_H) */

#ifdef __linux__
#define TRY_SEED_PROC_SYS_KERNEL_RANDOM_UUID
static int
arc4_seed_proc_sys_kernel_random_uuid(void)
{
	/* Occasionally, somebody will make /proc/sys accessible in a chroot,
	 * but not /dev/urandom.  Let's try /proc/sys/kernel/random/uuid.
	 * Its format is stupid, so we need to decode it from hex.
	 */
	int fd;
	char buf[128];
	unsigned char entropy[64];
	int bytes, n, i, nybbles;
	for (bytes = 0; bytes<ADD_ENTROPY; ) {
		fd = evutil_open_closeonexec_("/proc/sys/kernel/random/uuid", O_RDONLY, 0);
		if (fd < 0)
			return -1;
		n = read(fd, buf, sizeof(buf));
		close(fd);
		if (n<=0)
			return -1;
		memset(entropy, 0, sizeof(entropy));
		for (i=nybbles=0; i<n; ++i) {
			if (EVUTIL_ISXDIGIT_(buf[i])) {
				int nyb = evutil_hex_char_to_int_(buf[i]);
				if (nybbles & 1) {
					entropy[nybbles/2] |= nyb;
				} else {
					entropy[nybbles/2] |= nyb<<4;
				}
				++nybbles;
			}
		}
		if (nybbles < 2)
			return -1;
		arc4_addrandom(entropy, nybbles/2);
		bytes += nybbles/2;
	}
	evutil_memclear_(entropy, sizeof(entropy));
	evutil_memclear_(buf, sizeof(buf));
	return 0;
}
#endif

#ifndef _WIN32
#define TRY_SEED_URANDOM
static char *arc44random_urandom_filename = NULL;

static int arc4_seed_urandom_helper_(const char *fname)
{
    unsigned char buf[ADD_ENTROPY];
    int fd;
    size_t n;

    fd = evutil_open_closeonexec_(fname, O_RDONLY, 0);
    if (fd<0)
        return -1;
    n = read_all(fd, buf, sizeof(buf));
    close(fd);
    if (n != sizeof(buf))
        return -1;
    arc4_addrandom(buf, sizeof(buf));
    evutil_memclear_(buf, sizeof(buf));
    return 0;
}

static int
arc4_seed_urandom(void)
{
    /* This is adapted from Tor's crypto_seed_rng() */
    static const char *filenames[] = {
            "/dev/srandom", "/dev/urandom", "/dev/random", NULL
    };
    int i;
    if (arc44random_urandom_filename)
        return arc4_seed_urandom_helper_(arc44random_urandom_filename);

    for (i = 0; filenames[i]; ++i) {
        if (arc4_seed_urandom_helper_(filenames[i]) == 0) {
            return 0;
        }
    }

    return -1;
}
#endif

static int
arc4_seed(void)
{
    int ok = 0;
    /* We try every method that might work, and don't give up even if one
     * does seem to work.  There's no real harm in over-seeding, and if
     * one of these sources turns out to be broken, that would be bad. */
#ifdef TRY_SEED_WIN32
    if (0 == arc4_seed_win32())
		ok = 1;
#endif
#ifdef TRY_SEED_GETRANDOM
    if (0 == arc4_seed_getrandom())
		ok = 1;
#endif
#ifdef TRY_SEED_URANDOM
    if (0 == arc4_seed_urandom())
        ok = 1;
#endif
#ifdef TRY_SEED_PROC_SYS_KERNEL_RANDOM_UUID
    if (arc44random_urandom_filename == NULL &&
	    0 == arc4_seed_proc_sys_kernel_random_uuid())
		ok = 1;
#endif
#ifdef TRY_SEED_SYSCTL_BSD
    if (0 == arc4_seed_sysctl_bsd())
		ok = 1;
#endif
    return ok ? 0 : -1;
}

static inline unsigned int
arc4_getword(void);
static int
arc4_stir(void)
{
    int     i;
    uint32_t rekey_fuzz;

    if (!rs_initialized) {
        arc4_init();
        rs_initialized = 1;
    }

    if (0 != arc4_seed())
        return -1;

    /*
     * Discard early keystream, as per recommendations in
     * "Weaknesses in the Key Scheduling Algorithm of RC4" by
     * Scott Fluhrer, Itsik Mantin, and Adi Shamir.
     * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
     *
     * Ilya Mironov's "(Not So) Random Shuffles of RC4" suggests that
     * we drop at least 2*256 bytes, with 12*256 as a conservative
     * value.
     *
     * RFC4345 says to drop 6*256.
     *
     * At least some versions of this code drop 4*256, in a mistaken
     * belief that "words" in the Fluhrer/Mantin/Shamir paper refers
     * to processor words.
     *
     * We add another sect to the cargo cult, and choose 12*256.
     */
    for (i = 0; i < 12*256; i++)
        (void)arc4_getbyte();

    rekey_fuzz = arc4_getword();
    /* rekey interval should not be predictable */
    arc4_count = REKEY_BASE + (rekey_fuzz % REKEY_BASE);

    return 0;
}


static void
arc4_stir_if_needed(void)
{
    pid_t pid = getpid();

    if (arc4_count <= 0 || !rs_initialized || arc4_stir_pid != pid)
    {
        arc4_stir_pid = pid;
        arc4_stir();
    }
}

static inline unsigned char
arc4_getbyte(void)
{
    unsigned char si, sj;

    rs.i = (rs.i + 1);
    si = rs.s[rs.i];
    rs.j = (rs.j + si);
    sj = rs.s[rs.j];
    rs.s[rs.i] = sj;
    rs.s[rs.j] = si;
    return (rs.s[(si + sj) & 0xff]);
}

static inline unsigned int
arc4_getword(void)
{
    unsigned int val;

    val = (unsigned)arc4_getbyte() << 24;
    val |= arc4_getbyte() << 16;
    val |= arc4_getbyte() << 8;
    val |= arc4_getbyte();

    return val;
}

#ifndef arc44random_NOSTIR
 int
arc44random_stir(void)
{
    int val;
    ARC4_LOCK_();
    val = arc4_stir();
    ARC4_UNLOCK_();
    return val;
}
#endif

#ifndef arc44random_NOADDRANDOM
 void
arc44random_addrandom(const unsigned char *dat, int datlen)
{
    int j;
    ARC4_LOCK_();
    if (!rs_initialized)
        arc4_stir();
    for (j = 0; j < datlen; j += 256) {
        /* arc4_addrandom() ignores all but the first 256 bytes of
         * its input.  We want to make sure to look at ALL the
         * data in 'dat', just in case the user is doing something
         * crazy like passing us all the files in /var/log. */
        arc4_addrandom(dat + j, datlen - j);
    }
    ARC4_UNLOCK_();
}
#endif

#ifndef arc44random_NORANDOM
 uint32_t
arc44random(void)
{
    uint32_t val;
    ARC4_LOCK_();
    arc4_count -= 4;
    arc4_stir_if_needed();
    val = arc4_getword();
    ARC4_UNLOCK_();
    return val;
}
#endif

#ifndef EVENT__HAVE_arc44random_BUF
 void
arc44random_buf(void *buf_, size_t n)
{
    unsigned char *buf = buf_;
    ARC4_LOCK_();
    arc4_stir_if_needed();
    while (n--) {
        if (--arc4_count <= 0)
            arc4_stir();
        buf[n] = arc4_getbyte();
    }
    ARC4_UNLOCK_();
}
#endif  /* #ifndef EVENT__HAVE_arc44random_BUF */

#ifndef arc44random_NOUNIFORM
/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
 unsigned int
arc44random_uniform(unsigned int upper_bound)
{
    uint32_t r, min;

    if (upper_bound < 2)
        return 0;

    /* 2**32 % x == (2**32 - x) % x */
    min = -upper_bound % upper_bound;

    /*
     * This could theoretically loop forever but each retry has
     * p > 0.5 (worst case, usually far better) of selecting a
     * number inside the range we need, so it should rarely need
     * to re-roll.
     */
    for (;;) {
        r = arc44random();
        if (r >= min)
            break;
    }

    return r % upper_bound;
}
#endif
