/*
 * os-posix-lib.c
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2010 Red Hat, Inc.
 *
 * QEMU library functions on POSIX which are shared between QEMU and
 * the QEMU tools.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* The following block of code temporarily renames the daemon() function so the
   compiler does not see the warning associated with it in stdlib.h on OSX */
#ifdef __APPLE__
#define daemon qemu_fake_daemon_function
#include <stdlib.h>
#undef daemon
extern int daemon(int, int);
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__arm__))
   /* Use 2 MiB alignment so transparent hugepages can be used by KVM.
      Valgrind does not support alignments larger than 1 MiB,
      therefore we need special code which handles running on Valgrind. */
#  define QEMU_VMALLOC_ALIGN (512 * 4096)
#elif defined(__linux__) && defined(__s390x__)
   /* Use 1 MiB (segment size) alignment so gmap can be used by KVM. */
#  define QEMU_VMALLOC_ALIGN (256 * 4096)
#else
#  define QEMU_VMALLOC_ALIGN getpagesize()
#endif

#include <glib/gprintf.h>

#include "config-host.h"
#include "qemu-common.h"
#include "sysemu/sysemu.h"
#include "trace.h"
#include "qemu/sockets.h"
#include <sys/mman.h>

#ifdef CONFIG_LINUX
#include <sys/syscall.h>
#endif

int qemu_get_thread_id(void)
{
#if defined(__linux__)
    return syscall(SYS_gettid);
#else
    return getpid();
#endif
}

int qemu_daemon(int nochdir, int noclose)
{
    return daemon(nochdir, noclose);
}

void *qemu_oom_check(void *ptr)
{
    if (ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
        abort();
    }
    return ptr;
}

void *qemu_memalign(size_t alignment, size_t size)
{
    void *ptr;
#if defined(_POSIX_C_SOURCE) && !defined(__sun__) || defined(__APPLE__)
    int ret;
    ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0) {
        fprintf(stderr, "Failed to allocate %zu B: %s\n",
                size, strerror(ret));
        abort();
    }
#elif defined(GF_BSD_HOST_OS)
    ptr = qemu_oom_check(valloc(size));
#else
    ptr = qemu_oom_check(memalign(alignment, size));
#endif
    trace_qemu_memalign(alignment, size, ptr);
    return ptr;
}

/* alloc shared memory pages */
void *qemu_anon_ram_alloc(size_t size)
{
    size_t align = QEMU_VMALLOC_ALIGN;
    size_t total = size + align - getpagesize();
    void *ptr = mmap(0, total, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    size_t offset = QEMU_ALIGN_UP((uintptr_t)ptr, align) - (uintptr_t)ptr;

    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Failed to allocate %zu B: %s\n",
                size, strerror(errno));
        abort();
    }

    ptr += offset;
    total -= offset;

    if (offset > 0) {
        munmap(ptr - offset, offset);
    }
    if (total > size) {
        munmap(ptr + size, total - size);
    }

    trace_qemu_anon_ram_alloc(size, ptr);
    return ptr;
}

void qemu_vfree(void *ptr)
{
    trace_qemu_vfree(ptr);
    free(ptr);
}

void qemu_anon_ram_free(void *ptr, size_t size)
{
    trace_qemu_anon_ram_free(ptr, size);
    if (ptr) {
        munmap(ptr, size);
    }
}

void qemu_set_block(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f & ~O_NONBLOCK);
}

void qemu_set_nonblock(int fd)
{
    int f;
    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

void qemu_set_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

/*
 * Creates a pipe with FD_CLOEXEC set on both file descriptors
 */
int qemu_pipe(int pipefd[2])
{
    int ret;

#ifdef CONFIG_PIPE2
#ifdef pipe2
    ret = pipe2(pipefd, O_CLOEXEC);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif
#endif
    ret = pipe(pipefd);
    if (ret == 0) {
        qemu_set_cloexec(pipefd[0]);
        qemu_set_cloexec(pipefd[1]);
    }

    return ret;
}

#ifndef UTIME_NOW
#define UTIME_NOW	((1l << 30) - 1l)
#endif
#ifndef UTIME_OMIT
#define UTIME_OMIT	((1l << 30) - 2l)
#endif


int qemu_utimens(const char *path, const struct timespec *times)
{
    struct timeval tv[2], tv_now;
    struct stat st;
    int i;
#if defined(CONFIG_UTIMENSAT)
#ifdef utimensat
    int ret;

    ret = utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif
#endif
    /* Fallback: use utimes() instead of utimensat() */

    /* happy if special cases */
    if (times[0].tv_nsec == UTIME_OMIT && times[1].tv_nsec == UTIME_OMIT) {
        return 0;
    }
    if (times[0].tv_nsec == UTIME_NOW && times[1].tv_nsec == UTIME_NOW) {
        return utimes(path, NULL);
    }

    /* prepare for hard cases */
    if (times[0].tv_nsec == UTIME_NOW || times[1].tv_nsec == UTIME_NOW) {
        gettimeofday(&tv_now, NULL);
    }
    if (times[0].tv_nsec == UTIME_OMIT || times[1].tv_nsec == UTIME_OMIT) {
        stat(path, &st);
    }

    for (i = 0; i < 2; i++) {
        if (times[i].tv_nsec == UTIME_NOW) {
            tv[i].tv_sec = tv_now.tv_sec;
            tv[i].tv_usec = tv_now.tv_usec;
        } else if (times[i].tv_nsec == UTIME_OMIT) {
            tv[i].tv_sec = (i == 0) ? st.st_atime : st.st_mtime;
            tv[i].tv_usec = 0;
        } else {
            tv[i].tv_sec = times[i].tv_sec;
            tv[i].tv_usec = times[i].tv_nsec / 1000;
        }
    }

    return utimes(path, &tv[0]);
}

char *
qemu_get_local_state_pathname(const char *relative_pathname)
{
    return g_strdup_printf("%s/%s", CONFIG_QEMU_LOCALSTATEDIR,
                           relative_pathname);
}
